package enforcement

import (
	"reflect"
	"testing"
)

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"coordinator.example:8080": "coordinator.example",
		"stun:1.2.3.4:3478":        "1.2.3.4",
		"turn:turn.example:3478":   "turn.example",
		"1.2.3.4:8080":             "1.2.3.4",
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

func TestResolveExclusionsDedupesLiteralIPs(t *testing.T) {
	got := resolveExclusions("1.2.3.4:8080", "stun:1.2.3.4:3478", "turn:5.6.7.8:3478")
	want := []string{"1.2.3.4", "5.6.7.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveExclusions = %v, want %v", got, want)
	}
}

func TestResolveExclusionsSkipsUnparseable(t *testing.T) {
	got := resolveExclusions("not-a-valid-endpoint", "1.2.3.4:8080")
	want := []string{"1.2.3.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveExclusions = %v, want %v", got, want)
	}
}

func TestEnsureCIDR(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":       "1.2.3.4/32",
		"1.2.3.4/32":    "1.2.3.4/32",
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
	got := resolveExclusionsV6("1.2.3.4:8080", "not-a-valid-endpoint")
	if len(got) != 0 {
		t.Fatalf("resolveExclusionsV6 = %v, want none (IPv4-literal and unparseable inputs)", got)
	}
}

func TestResolveExclusionsSkipsIPv6(t *testing.T) {
	// The IPv4-only function must not pick up a v6 literal meant for its v6
	// counterpart — each endpoint belongs to exactly one of the two result
	// sets, never both.
	got := resolveExclusions("[2001:db8::1]:443", "1.2.3.4:8080")
	want := []string{"1.2.3.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveExclusions = %v, want %v (must skip the IPv6 literal)", got, want)
	}
}

func TestIsIPv6Literal(t *testing.T) {
	cases := map[string]bool{
		"2001:db8::1": true,
		"::1":         true,
		"1.2.3.4":     false,
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
		{"bare ipv4", "1.2.3.4", "<ip>"},
		{"ipv4 cidr", "1.2.3.4/32", "<ip>"},
		{"bare ipv6", "2001:db8::1", "<ip>"},
		{"ipv6 cidr", "2001:db8::1/128", "<ip>"},
		{"ipv6 loopback shorthand", "::1", "<ip>"},
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
