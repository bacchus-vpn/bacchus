//go:build windows

package main

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"coordinator.example:8080": "coordinator.example",
		"stun:192.0.2.4:3478":      "192.0.2.4",
		"turn:turn.example:3478":   "turn.example",
		"192.0.2.4:8080":           "192.0.2.4",
		"not-a-valid-endpoint":     "",
		"":                         "",
		// Bracketed IPv6 (issue #117): the "count 2+ colons -> drop a leading
		// scheme" heuristic used to fire on these too, slicing into the
		// address itself instead of leaving it for net.SplitHostPort, which
		// already understands the bracket form natively.
		"[2001:db8::1]:443": "2001:db8::1",
		"[::1]:8080":        "::1",
	}
	for in, want := range cases {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestNewPSCmdRunsWindowless guards the console-window fix: every powershell.exe
// the client spawns must carry CREATE_NO_WINDOW, or a -H=windowsgui process
// flashes a console window on each of the many calls runPS makes.
func TestNewPSCmdRunsWindowless(t *testing.T) {
	cmd := newPSCmd("Write-Output hi")
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Fatalf("newPSCmd must set CREATE_NO_WINDOW (%#x); got SysProcAttr=%+v", createNoWindow, cmd.SysProcAttr)
	}
}

func TestResolveExclusionsDedupesLiteralIPs(t *testing.T) {
	got := resolveExclusions("192.0.2.4:8080", "stun:192.0.2.4:3478", "turn:192.0.2.8:3478")
	want := []string{"192.0.2.4", "192.0.2.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveExclusions = %v, want %v", got, want)
	}
}

func TestResolveExclusionsSkipsUnparseable(t *testing.T) {
	got := resolveExclusions("not-a-valid-endpoint", "192.0.2.4:8080")
	want := []string{"192.0.2.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveExclusions = %v, want %v", got, want)
	}
}

func TestEnsureCIDR(t *testing.T) {
	cases := map[string]string{
		"192.0.2.4":     "192.0.2.4/32",
		"192.0.2.4/32":  "192.0.2.4/32",
		"10.0.0.0/8":    "10.0.0.0/8",
		"2001:db8::1":   "2001:db8::1/128", // issue #117: removeRoutes reaps IPv6 exclusions through this same helper
		"::1":           "::1/128",
		"2001:db8::/32": "2001:db8::/32", // already a CIDR — passes through regardless of family
	}
	for in, want := range cases {
		if got := ensureCIDR(in); got != want {
			t.Errorf("ensureCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveExclusionsV6(t *testing.T) {
	got := resolveExclusionsV6("[2001:db8::1]:443", "[2001:db8::2]:443")
	want := []string{"2001:db8::1", "2001:db8::2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveExclusionsV6 = %v, want %v", got, want)
	}
}

func TestResolveExclusionsV6SkipsIPv4(t *testing.T) {
	got := resolveExclusionsV6("192.0.2.4:8080", "not-a-valid-endpoint")
	if len(got) != 0 {
		t.Fatalf("resolveExclusionsV6 = %v, want none (IPv4-literal and unparseable inputs)", got)
	}
}

func TestResolveExclusionsSkipsIPv6(t *testing.T) {
	// The IPv4-only function must not pick up a v6 literal meant for its v6
	// counterpart — each endpoint belongs to exactly one of the two result
	// sets, never both.
	got := resolveExclusions("[2001:db8::1]:443", "192.0.2.4:8080")
	want := []string{"192.0.2.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveExclusions = %v, want %v (must skip the IPv6 literal)", got, want)
	}
}

func TestIsIPv6Literal(t *testing.T) {
	cases := map[string]bool{
		"2001:db8::1": true,
		"::1":         true,
		"192.0.2.4":   false,
		"not-an-ip":   false,
		"":            false,
	}
	for in, want := range cases {
		if got := isIPv6Literal(in); got != want {
			t.Errorf("isIPv6Literal(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestFirstLine guards the other half of issue #140: PowerShell's multi-line
// "At line:N char:M" position block re-echoes the failing source line (in
// the OS display language, and sometimes console-width-truncated mid-token),
// which can hand redactIPs a partial address fragment it can't recognize as
// a complete IP. Cutting to the first line before redacting removes that
// block entirely rather than trying to pattern-match around it.
func TestFirstLine(t *testing.T) {
	cases := map[string]string{
		"single line, no newline": "single line, no newline",
		"first\nsecond\nthird":    "first",
		"":                        "",
		"\nsecond":                "",
	}
	for in, want := range cases {
		if got := firstLine(in); got != want {
			t.Errorf("firstLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRedactIPs guards issue #140: a PowerShell command line or error string
// naming a real coordinator/exit/relay address must not reach bacchus.log
// intact. Table cases mirror the actual shapes runPS sees in this package —
// addExclusionRoutes' single-line New-NetRoute, killswitch.go's comma-joined
// -RemoteAddress allow-list, and plain non-IP command text that must pass
// through untouched.
func TestRedactIPs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare ipv4", "192.0.2.4", "<ip>"},
		{"ipv4 cidr", "192.0.2.4/32", "<ip>"},
		{"bare ipv6", "2001:db8::1", "<ip>"},
		{"ipv6 cidr", "2001:db8::1/128", "<ip>"},
		{"ipv6 loopback shorthand", "::1", "<ip>"},
		{
			// issue #170: the plain-IPv6 alternative alone stops at the
			// first ".", so this used to redact only "::ffff:203" and
			// leave ".0.113.7" — 3 of 4 octets — exposed right next to it.
			"ipv4-mapped ipv6 is redacted whole, not just up to the first dot",
			"::ffff:203.0.113.7",
			"<ip>",
		},
		{
			"ipv4-mapped ipv6 with a prefix length",
			"::ffff:203.0.113.7/128",
			"<ip>",
		},
		{"empty string", "", ""},
		{
			"no IP present",
			`Set-NetFirewallProfile -All -DefaultOutboundAction Block -ErrorAction Stop`,
			`Set-NetFirewallProfile -All -DefaultOutboundAction Block -ErrorAction Stop`,
		},
		{
			"hex-and-colon text that isn't a valid address is left alone",
			"DEAD:BEEF",
			"DEAD:BEEF",
		},
		{
			// issue #170: net.ParseIP itself rejects a leading-zero octet as
			// ambiguous octal-vs-decimal (Go 1.17+) — correctly left
			// unredacted, not a gap, since it was never a real address.
			"leading-zero octets are not a real IP and stay unredacted",
			"192.168.001.010",
			"192.168.001.010",
		},
		{
			// issue #170: a 3-octet fragment never satisfies the 4-octet
			// shape, so it isn't even proposed as a candidate here. That is
			// a real leak, not a curiosity — PowerShell's hard wrap can cut
			// an address mid-token and firstLine keeps the leading part — so
			// it is closed one layer up, by redactTrailingIPFragment (see
			// TestLogSafeRedactsWrapTruncatedFragment). This case pins
			// redactIPs' own scope, and nothing more.
			"a truncated 3-octet fragment is not a candidate for redactIPs alone",
			"203.0.113",
			"203.0.113",
		},
		{
			"New-NetRoute command line: cmdlet/flags survive, both addresses redacted",
			`New-NetRoute -DestinationPrefix "203.0.113.7/32" -NextHop "203.0.113.1" -InterfaceIndex 5 -RouteMetric 1 -ErrorAction Stop | Out-Null`,
			`New-NetRoute -DestinationPrefix "<ip>" -NextHop "<ip>" -InterfaceIndex 5 -RouteMetric 1 -ErrorAction Stop | Out-Null`,
		},
		{
			"New-NetFirewallRule comma-joined -RemoteAddress allow-list (all entries redacted)",
			`New-NetFirewallRule -DisplayName "Bacchus-Allow-Remotes" -Group "Bacchus" -Direction Outbound -Action Allow -RemoteAddress "203.0.113.1","198.51.100.9" -ErrorAction Stop | Out-Null`,
			`New-NetFirewallRule -DisplayName "Bacchus-Allow-Remotes" -Group "Bacchus" -Direction Outbound -Action Allow -RemoteAddress "<ip>","<ip>" -ErrorAction Stop | Out-Null`,
		},
		{
			"split-default prefixes get swept up too — harmless but redacted uniformly",
			`New-NetRoute -InterfaceAlias "Bacchus" -DestinationPrefix "0.0.0.0/1" -NextHop "10.66.0.2" -ErrorAction Stop | Out-Null`,
			`New-NetRoute -InterfaceAlias "Bacchus" -DestinationPrefix "<ip>" -NextHop "<ip>" -ErrorAction Stop | Out-Null`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactIPs(tc.in); got != tc.want {
				t.Errorf("redactIPs(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestLogSafeRedactsWrapTruncatedFragment closes the half of issue #170 that
// the first pass got wrong: redactIPs alone cannot see a partial address, and
// the claim that a partial one can never reach the log was false.
//
// powershell.exe wraps its rendered error at a fixed 119 columns even when
// stdout/stderr is a pipe rather than a console, and a token that cannot fit
// on a line of its own is hard-split at that column instead of moved down
// whole. When such a token carries an address — killswitch.go's comma-joined
// -RemoteAddress list is exactly that shape once the allow-list outgrows one
// line — the split can land mid-address, firstLine keeps the leading part,
// and 2 or 3 of 4 octets reach bacchus.log intact. The strings below were
// captured from a real powershell.exe run sweeping an address across the
// boundary (see TestLogSafeAgainstRealPowerShell for the live version).
func TestLogSafeRedactsWrapTruncatedFragment(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"three octets and a trailing dot", "prefixAAA203.0.113.", "prefixAAA<ip>"},
		{"three octets", "prefixAAA203.0.113", "prefixAAA<ip>"},
		{"two octets and a digit", "prefixAAA203.0.1", "prefixAAA<ip>"},
		{"two octets", "prefixAAA203.0", "prefixAAA<ip>"},
		{"one octet and a trailing dot", "prefixAAA203.", "prefixAAA<ip>"},
		{
			// Deliberately uncovered, and documented as such on
			// trailingIPFragmentPattern: a lone trailing number carries
			// almost nothing and is indistinguishable from an interface
			// index or a route metric.
			"a single trailing octet is left alone by design",
			"prefixAAA203", "prefixAAA203",
		},
		{
			// The fragment rule must not disturb a line that redactIPs
			// already handled: a complete literal is "<ip>" by then, so
			// there is no trailing digit run left to match.
			"a complete address is redacted by redactIPs and left alone here",
			`New-NetRoute -DestinationPrefix "203.0.113.7/32" -NextHop "203.0.113.1" -ErrorAction Stop`,
			`New-NetRoute -DestinationPrefix "<ip>" -NextHop "<ip>" -ErrorAction Stop`,
		},
		{
			"ordinary trailing command text is untouched",
			`Set-NetFirewallProfile -All -DefaultOutboundAction Block -ErrorAction Stop`,
			`Set-NetFirewallProfile -All -DefaultOutboundAction Block -ErrorAction Stop`,
		},
		{
			// firstLine still does its own half of the job: everything past
			// the first newline (PowerShell's position block) is dropped
			// before either redaction runs.
			"only the first line survives, redacted",
			"failed for 203.0.113.7\nAt line:1 char:1\n+ New-NetRoute -NextHop 203.0.113.1",
			"failed for <ip>",
		},
		{
			// The shape real powershell.exe actually produces: CRLF, so the
			// "\r" firstLine leaves behind sits between the fragment and the
			// end of the string. Anchored at the end, the fragment rule
			// silently matches nothing unless that "\r" is trimmed first —
			// this case is the one that caught it.
			"a CRLF line ending does not shield the fragment",
			"prefixAAA203.0.113\r\nAt line:1 char:1",
			"prefixAAA<ip>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := logSafe(tc.in); got != tc.want {
				t.Errorf("logSafe(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestLogSafeAgainstRealPowerShell drives the leak through the real thing
// rather than a hand-written approximation of it: a genuine powershell.exe
// failure whose echoed source line carries an address inside one
// unbreakable token, swept across the 119-column boundary one character at a
// time. Every offset must come back with no multi-octet fragment left in the
// line runPS would log.
//
// It also asserts the sweep is non-vacuous — that at least some offsets do
// leak without the fragment rule — so the test cannot quietly degrade into
// proving nothing if a future PowerShell stops wrapping this way.
//
// Skipped in -short: it launches one powershell.exe per offset.
func TestLogSafeAgainstRealPowerShell(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real powershell.exe wrap sweep in -short")
	}
	multiOctet := regexp.MustCompile(`[0-9]{1,3}\.[0-9]`)
	leakedWithoutTheRule := 0
	for pad := 94; pad <= 106; pad++ {
		// One token: padding, the address, then more padding so the token
		// cannot fit on a line by itself and must be hard-split.
		token := strings.Repeat("A", pad) + "203.0.113.7" + strings.Repeat("A", 60)
		out, err := newPSCmd(`Write-Error "` + token + `"`).CombinedOutput()
		if err == nil {
			t.Fatalf("pad=%d: expected the Write-Error call to fail", pad)
		}
		line := firstLine(strings.TrimSpace(string(out)))
		if !strings.Contains(line, "AAA") {
			t.Fatalf("pad=%d: powershell did not echo the source line, got %q", pad, line)
		}
		if multiOctet.MatchString(redactIPs(line)) {
			leakedWithoutTheRule++
		}
		if got := logSafe(string(out)); multiOctet.MatchString(got) {
			t.Errorf("pad=%d: logSafe left an address fragment in the logged line: %q", pad, got)
		}
	}
	if leakedWithoutTheRule == 0 {
		t.Fatal("no swept offset leaked through redactIPs alone — the sweep no longer reproduces the wrap, so it proves nothing")
	}
	t.Logf("%d of the swept offsets leak a multi-octet fragment through redactIPs alone", leakedWithoutTheRule)
}
