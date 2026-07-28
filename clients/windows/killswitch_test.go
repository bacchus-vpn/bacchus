//go:build windows

package main

import (
	"reflect"
	"testing"
)

func TestKillSwitchAllowIPsDedupesAndAppendsLoopback(t *testing.T) {
	got := killSwitchAllowIPs(
		[]string{"1.2.3.4", "5.6.7.8", "1.2.3.4"},           // control, with a dup
		[]string{"10.0.0.0/8", "5.6.7.8", "192.168.1.0/24"}, // bypass, overlapping control
	)
	want := []string{"1.2.3.4", "5.6.7.8", "10.0.0.0/8", "192.168.1.0/24", "127.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("killSwitchAllowIPs = %v, want %v", got, want)
	}
}

func TestKillSwitchAllowIPsEmptyStillHasLoopback(t *testing.T) {
	got := killSwitchAllowIPs(nil, nil)
	want := []string{"127.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("killSwitchAllowIPs(nil, nil) = %v, want %v", got, want)
	}
}

func TestKillSwitchAllowIPsSkipsBlank(t *testing.T) {
	got := killSwitchAllowIPs([]string{"", "  ", "1.2.3.4"}, []string{" "})
	want := []string{"1.2.3.4", "127.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("killSwitchAllowIPs = %v, want %v", got, want)
	}
}

// TestKillSwitchAllowIPsExcludesIPv6Loopback guards the fix for the kill-switch
// never arming: New-NetFirewallRule rejects ::1/128 (IPv6 loopback) in
// -RemoteAddress ("An unspecified, multicast, broadcast, or loopback IPv6
// address was specified"), which fails arming and, being fail-closed, tears the
// tunnel down. The IPv6 loopback must never be in the allow-list.
func TestKillSwitchAllowIPsExcludesIPv6Loopback(t *testing.T) {
	for _, ip := range killSwitchAllowIPs([]string{"1.2.3.4"}, nil) {
		if ip == "::1/128" {
			t.Fatal("allow-list must not contain ::1/128 — New-NetFirewallRule rejects an IPv6 loopback -RemoteAddress, which fails kill-switch arming")
		}
	}
}

func TestPSStringArray(t *testing.T) {
	if got := psStringArray([]string{"1.2.3.4", "10.0.0.0/8"}); got != `"1.2.3.4","10.0.0.0/8"` {
		t.Fatalf("psStringArray = %s", got)
	}
	if got := psStringArray(nil); got != "" {
		t.Fatalf("psStringArray(nil) = %q, want empty", got)
	}
}
