//go:build windows

package enforcement

import (
	"errors"
	"reflect"
	"strings"
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

// The tests below drive the real cmdlet sequence through winOS's injectable
// runner rather than a live firewall. They are the Windows half of parity
// items 2, 3 and 4 — the half that cannot be asserted portably, because what
// is being checked is which NetSecurity cmdlets run and in what order.
//
// They run on CI's windows-latest job (which now runs `go test`, not only
// `go build`) and need no elevation: nothing here shells out. What they
// cannot prove is that Windows honours the cmdlets — that a Block default
// really does survive this process dying — which is an OS guarantee and is
// recorded in ADR-0039's 2026-07-30 amendment against a live elevated run,
// not asserted here.

// recordingPS captures every script a winOS would have run, and can answer
// specific ones.
type recordingPS struct {
	scripts []string
	answers map[string]string
	fail    map[string]error
}

func newRecordingPS() *recordingPS {
	return &recordingPS{answers: map[string]string{}, fail: map[string]error{}}
}

// os returns a winOS wired to this recorder instead of powershell.exe.
func (r *recordingPS) os() *winOS {
	return &winOS{run: func(script string) (string, error) {
		r.scripts = append(r.scripts, script)
		for frag, err := range r.fail {
			if strings.Contains(script, frag) {
				return "", err
			}
		}
		for frag, out := range r.answers {
			if strings.Contains(script, frag) {
				return out, nil
			}
		}
		return "", nil
	}}
}

func (r *recordingPS) indexOf(fragment string) int {
	for i, s := range r.scripts {
		if strings.Contains(s, fragment) {
			return i
		}
	}
	return -1
}

// TestEnableKillSwitchAllowsBeforeItBlocks is parity item 2's ordering. The
// default outbound action must flip to Block only after every allow rule
// exists; reversed, the machine is fail-closed with no allowlist for as long
// as the remaining cmdlets take, which cuts the tunnel's own control plane
// and tears the session down from under itself.
func TestEnableKillSwitchAllowsBeforeItBlocks(t *testing.T) {
	r := newRecordingPS()
	r.answers["Get-NetFirewallProfile"] = "Domain=Allow;Private=Allow;Public=Allow"

	if err := r.os().enableKillSwitch([]string{"192.0.2.10"}, []string{"198.51.100.0/24"}); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}

	block := r.indexOf("DefaultOutboundAction Block")
	if block < 0 {
		t.Fatalf("the outbound default was never set to Block; scripts: %v", r.scripts)
	}
	// Matched on the CREATE specifically, not on the rule name: enableKillSwitch
	// calls recoverKillSwitch first, which reads the marker rule by the same
	// name, so a bare name match finds that read and silently checks the
	// wrong script.
	for _, rule := range []string{"Bacchus-Allow-Tunnel", "Bacchus-Allow-Remotes", "Bacchus-Allow-DHCP", "BacchusKillSwitch-Marker"} {
		create := `New-NetFirewallRule -DisplayName "` + rule + `"`
		i := r.indexOf(create)
		if i < 0 {
			t.Errorf("allow rule %q was never created; scripts: %v", rule, r.scripts)
			continue
		}
		if i > block {
			t.Errorf("%q was created AFTER the default flipped to Block — the machine is fail-closed without it for that window", rule)
		}
	}
	// The marker carries the prior state, which is the only way a crashed
	// session's lockdown can ever be undone (parity item 3).
	marker := r.indexOf(`New-NetFirewallRule -DisplayName "BacchusKillSwitch-Marker"`)
	if marker >= 0 && !strings.Contains(r.scripts[marker], "Domain=Allow;Private=Allow;Public=Allow") {
		t.Errorf("the marker rule does not carry the prior outbound state, so a crash leaves nothing to restore from: %q", r.scripts[marker])
	}
}

// TestEnableKillSwitchLeavesNothingHalfArmed covers the failure path: if any
// step after the first fails, the whole rule group is removed rather than
// left partially installed for the next launch's recovery to misread.
func TestEnableKillSwitchLeavesNothingHalfArmed(t *testing.T) {
	r := newRecordingPS()
	r.answers["Get-NetFirewallProfile"] = "Domain=Allow;Private=Allow;Public=Allow"
	r.fail["Bacchus-Allow-DHCP"] = errors.New("simulated cmdlet failure")

	if err := r.os().enableKillSwitch([]string{"192.0.2.10"}, nil); err == nil {
		t.Fatal("enableKillSwitch reported success despite a failing cmdlet")
	}
	if r.indexOf("DefaultOutboundAction Block") >= 0 {
		t.Errorf("a failed arming still flipped the machine to Block; scripts: %v", r.scripts)
	}
	if r.indexOf(`Remove-NetFirewallRule -Group "BacchusKillSwitch"`) < 0 {
		t.Errorf("a failed arming left its rules behind; scripts: %v", r.scripts)
	}
}

// TestRecoverKillSwitchRestoresACrashedSession is parity item 3. A lockdown
// left behind by a killed prior session is detected via the marker rule and
// lifted, restoring the exact prior per-profile state rather than guessing
// "Allow".
func TestRecoverKillSwitchRestoresACrashedSession(t *testing.T) {
	r := newRecordingPS()
	r.answers["BacchusKillSwitch-Marker"] = "Domain=Allow;Private=Block;Public=NotConfigured"

	r.os().recoverKillSwitch()

	for _, want := range []string{
		"Set-NetFirewallProfile -Name Domain -DefaultOutboundAction Allow",
		"Set-NetFirewallProfile -Name Private -DefaultOutboundAction Block",
		"Set-NetFirewallProfile -Name Public -DefaultOutboundAction NotConfigured",
	} {
		if r.indexOf(want) < 0 {
			t.Errorf("recovery did not restore the recorded prior state (%q); scripts: %v", want, r.scripts)
		}
	}
	if r.indexOf(`Remove-NetFirewallRule -Group "BacchusKillSwitch"`) < 0 {
		t.Errorf("recovery restored the default action but left the rule group behind; scripts: %v", r.scripts)
	}
}

// TestRecoverKillSwitchIsANoopWithoutAMarker: a clean launch must not touch
// the firewall at all. Restoring "Allow" unconditionally would silently undo
// an outbound-block policy the user or their administrator set themselves.
func TestRecoverKillSwitchIsANoopWithoutAMarker(t *testing.T) {
	r := newRecordingPS() // no marker answer: reads back ""
	r.os().recoverKillSwitch()

	if r.indexOf("Set-NetFirewallProfile") >= 0 {
		t.Errorf("recovery changed firewall state with no lockdown to recover from; scripts: %v", r.scripts)
	}
	if r.indexOf("Remove-NetFirewallRule") >= 0 {
		t.Errorf("recovery removed rules with no lockdown to recover from; scripts: %v", r.scripts)
	}
}

// TestRefreshKillSwitchAllowIPAddsToTheLiveRule is parity item 4. A bypass
// domain that resolves mid-session has to join the live allowlist; without
// it, that destination works until the lockdown arms and then silently stops
// — a functional regression wearing a security feature's clothes.
func TestRefreshKillSwitchAllowIPAddsToTheLiveRule(t *testing.T) {
	r := newRecordingPS()
	r.answers["Get-NetFirewallAddressFilter"] = "192.0.2.10,127.0.0.0/8"

	r.os().refreshKillSwitchAllowIP("198.51.100.7")

	i := r.indexOf(`New-NetFirewallRule -DisplayName "Bacchus-Allow-Remotes"`)
	if i < 0 {
		t.Fatalf("the allow-remotes rule was never recreated; scripts: %v", r.scripts)
	}
	for _, want := range []string{"192.0.2.10", "127.0.0.0/8", "198.51.100.7"} {
		if !strings.Contains(r.scripts[i], want) {
			t.Errorf("the refreshed allowlist dropped %s: %q", want, r.scripts[i])
		}
	}
	if del := r.indexOf(`Remove-NetFirewallRule -DisplayName "Bacchus-Allow-Remotes"`); del < 0 || del > i {
		t.Errorf("the old rule must be removed before the replacement is created (NetSecurity has no in-place edit); scripts: %v", r.scripts)
	}
}

// TestRefreshKillSwitchAllowIPIsANoopWhenUnarmed: when the kill-switch is not
// armed the rule does not exist, the read fails, and this must do nothing
// rather than create an allow rule that outlives an unarmed session.
func TestRefreshKillSwitchAllowIPIsANoopWhenUnarmed(t *testing.T) {
	r := newRecordingPS()
	r.fail["Get-NetFirewallAddressFilter"] = errors.New("rule not found")

	r.os().refreshKillSwitchAllowIP("198.51.100.7")

	if r.indexOf("New-NetFirewallRule") >= 0 {
		t.Errorf("a live refresh created a firewall rule while the kill-switch was unarmed; scripts: %v", r.scripts)
	}
}

// TestABypassPrefixSurvivesIntoTheFirewallRule closes bacchus#258's loop on the
// side the card actually measured: it added `100.64.0.0/10` to `bypass`, and the
// resulting `Bacchus-Allow-Remotes` rule came back byte-identical to the one
// before it — loopback, the coordinator, and the addresses resolved from the ten
// host names already there.
//
// The classifier keeps the prefix (splittunnel_test.go) and this is the other
// end of the same wire: the value `tunnel.go` hands to enableKillSwitch reaches
// `-RemoteAddress` in the generated cmdlet, quoted, alongside the resolved hosts
// rather than instead of them.
//
// Mutation check: drop the bypass loop in killSwitchAllowIPs and this names the
// range that went missing from the rule.
func TestABypassPrefixSurvivesIntoTheFirewallRule(t *testing.T) {
	r := newRecordingPS()
	r.answers["Get-NetFirewallProfile"] = "Domain=Allow;Private=Allow;Public=Allow"

	control := []string{"192.0.2.10"}                   // the coordinator
	bypass := []string{"100.64.0.0/10", "198.51.100.4"} // one range, one resolved host
	if err := r.os().enableKillSwitch(control, bypass); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}

	i := r.indexOf(fwAllowRemotesName)
	if i < 0 {
		t.Fatal("no allow-remotes rule was created")
	}
	rule := r.scripts[i]
	for _, want := range []string{`"100.64.0.0/10"`, `"198.51.100.4"`, `"192.0.2.10"`, `"127.0.0.0/8"`} {
		if !strings.Contains(rule, want) {
			t.Errorf("the allow-remotes rule does not carry %s — that destination is blocked while connected:\n%s", want, rule)
		}
	}
}
