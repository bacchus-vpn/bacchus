//go:build windows

// Fail-closed kill-switch. While the tunnel is up, the machine's outbound
// default action is flipped to Block and a narrow allowlist is installed, so
// nothing egresses in the clear even if the tunnel — or this whole process —
// dies. A killed process's wintun adapter is auto-removed and its routes
// vanish, which would otherwise resurface the physical default route and leak;
// an OS-level firewall filter is the only thing that keeps blocking after we
// are gone, so that is what enforces this.
//
// The allowlist is deliberately tiny:
//   - everything on the tunnel adapter itself (so tunnelled apps work),
//   - the control-plane endpoints (coordinator/STUN/TURN) on any interface,
//     so the underlying WebRTC session keeps flowing,
//   - the configured split-tunnel bypass destinations (splittunnel.go), so
//     they keep working even under lockdown — including addresses a bypass
//     domain resolves to *after* the lockdown is already armed, which
//     refreshKillSwitchAllowIP folds in live rather than waiting for the
//     next connect. This only holds because splittunnel.go's arm() and
//     learn() share one lock across the exact moment arming happens (issue
//     #73) — without that, an address learned right around arming could
//     miss both the initial allowlist snapshot and the live refresh,
//     leaving it wrongly blocked rather than working under lockdown,
//   - loopback (the local SOCKS server) and DHCP (to keep the lease alive).
//
// Note there is deliberately no plaintext-DNS allowance: DNS is resolved over
// TCP through the tunnel (see tun2socks.go), so the lockdown can't leak a
// lookup.
//
// This allowlist is the same regardless of split-tunnel mode, which has a
// real consequence worth calling out: in "include" mode, the bypass list is
// the *tunnelled* set and "direct" is everything else (splittunnel.go) — but
// that "everything else" traffic is not allow-listed here, so arming the
// kill-switch blocks it too, for as long as it's connected, rather than
// leaving it alone as traffic that was never meant to be protected. Fails
// safe (nothing leaks), but it's a real UX question this package doesn't
// attempt to solve — see the client README and ADR-0025's amendment.
//
// Crash recovery: the prior DefaultOutboundAction is stashed in a marker
// firewall rule's Description so it survives our death. recoverKillSwitch,
// run at startup, undoes a lockdown left behind by a crashed session.
package enforcement

import (
	"fmt"
	"strings"
)

const (
	fwGroup            = "BacchusKillSwitch"
	fwMarkerName       = "BacchusKillSwitch-Marker"
	fwAllowRemotesName = "Bacchus-Allow-Remotes"
)

// killSwitchAllowIPs assembles the remote-address allowlist for the lockdown:
// the control-plane IPs plus the configured bypass entries (IPs or CIDRs),
// always including loopback. Order-preserving and de-duplicated so the
// generated firewall rule is stable.
func killSwitchAllowIPs(control, bypass []string) []string {
	out := make([]string, 0, len(control)+len(bypass)+2)
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, c := range control {
		add(c)
	}
	for _, b := range bypass {
		add(b)
	}
	// IPv4 loopback only. New-NetFirewallRule rejects an IPv6 loopback address
	// (::1/128) in -RemoteAddress — "An unspecified, multicast, broadcast, or
	// loopback IPv6 address was specified" — which fails the whole arming and, being
	// fail-closed, tears the tunnel down. It's unnecessary anyway: IPv6 is disabled
	// on the physical adapter while the tunnel is up (disablePhysicalIPv6), and the
	// local SOCKS server is reached over IPv4 loopback.
	add("127.0.0.0/8")
	return out
}

// enableKillSwitch installs the allowlist and flips the outbound default to
// Block. control is the set of control-plane IPs already excluded from the
// tunnel route; bypass is the configured split-tunnel bypass list.
func (o *winOS) enableKillSwitch(control, bypass []string) error {
	// Clear any stale lockdown first (e.g. a prior crash) so we start clean
	// and capture a true prior state rather than our own leftover Block.
	o.recoverKillSwitch()

	prior, err := o.readDefaultOutboundActions()
	if err != nil {
		return fmt.Errorf("kill-switch: read firewall state: %w", err)
	}

	// Any failure past this point must leave nothing half-armed behind.
	armed := false
	defer func() {
		if !armed {
			o.removeKillSwitchRules()
		}
	}()

	// Allow rules (evaluated because the default action becomes Block).
	if _, err := o.runPS(fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "Bacchus-Allow-Tunnel" -Group "%s" -Direction Outbound -Action Allow -InterfaceAlias "%s" -ErrorAction Stop | Out-Null`,
		fwGroup, tunAdapterName)); err != nil {
		return fmt.Errorf("kill-switch: allow tunnel adapter: %w", err)
	}
	allow := killSwitchAllowIPs(control, bypass)
	if _, err := o.runPS(fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "%s" -Group "%s" -Direction Outbound -Action Allow -RemoteAddress %s -ErrorAction Stop | Out-Null`,
		fwAllowRemotesName, fwGroup, psStringArray(allow))); err != nil {
		return fmt.Errorf("kill-switch: allow remotes: %w", err)
	}
	// Keep the DHCP lease alive so the physical link doesn't drop from under us.
	if _, err := o.runPS(fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "Bacchus-Allow-DHCP" -Group "%s" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 67 -LocalPort 68 -ErrorAction Stop | Out-Null`,
		fwGroup)); err != nil {
		return fmt.Errorf("kill-switch: allow dhcp: %w", err)
	}

	// Marker rule: its presence means "we flipped the default action", and its
	// Description carries the prior state so a crashed session can be restored.
	if _, err := o.runPS(fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "%s" -Group "%s" -Direction Outbound -Action Allow -Enabled False -RemoteAddress 127.0.0.1 -Description "%s" -ErrorAction Stop | Out-Null`,
		fwMarkerName, fwGroup, prior)); err != nil {
		return fmt.Errorf("kill-switch: write marker: %w", err)
	}

	if _, err := o.runPS(`Set-NetFirewallProfile -All -DefaultOutboundAction Block -ErrorAction Stop`); err != nil {
		return fmt.Errorf("kill-switch: set default block: %w", err)
	}
	armed = true
	return nil
}

// disableKillSwitch restores the prior outbound default and removes the
// allowlist. Safe to call even if the kill-switch is not currently armed.
func (o *winOS) disableKillSwitch() {
	prior := o.readMarkerPriorState()
	if prior != "" {
		o.restoreDefaultOutboundActions(prior)
	}
	o.removeKillSwitchRules()
}

// recoverKillSwitch undoes a lockdown left behind by a crashed prior session.
// Called at startup and again defensively before arming. Idempotent: a no-op
// when no marker is present.
func (o *winOS) recoverKillSwitch() {
	prior := o.readMarkerPriorState()
	if prior == "" {
		return
	}
	o.restoreDefaultOutboundActions(prior)
	o.removeKillSwitchRules()
}

func (o *winOS) removeKillSwitchRules() {
	_, _ = o.runPS(fmt.Sprintf(
		`Remove-NetFirewallRule -Group "%s" -ErrorAction SilentlyContinue`, fwGroup))
}

// refreshKillSwitchAllowIP adds ip to the live allow-remotes rule, if the
// kill-switch is currently armed. Called when splittunnel.go's policy learns
// a new bypass address mid-session (a domain resolved for the first time, or
// to an address not seen before) — without this, that address would only be
// protected once the *next* connection re-runs enableKillSwitch, leaving a
// session-length gap where the lockdown could engage without it.
//
// NetSecurity's cmdlets have no in-place "add one address" edit, so this
// reads the rule's current list, removes the rule, and recreates it with ip
// appended — a brief window with no explicit allow rule for the addresses it
// covered. That fails *closed*: the default action is already Block, so a
// connection racing the gap is blocked, not leaked. Best-effort throughout —
// if the rule can't be read (e.g. the kill-switch isn't armed), this is a
// silent no-op rather than an error the caller has to handle.
func (o *winOS) refreshKillSwitchAllowIP(ip string) {
	current, err := o.runPS(fmt.Sprintf(
		`(Get-NetFirewallRule -DisplayName "%s" -ErrorAction Stop |
			Get-NetFirewallAddressFilter -ErrorAction Stop).RemoteAddress -join ","`,
		fwAllowRemotesName))
	if err != nil || current == "" {
		return
	}
	allow := append(strings.Split(current, ","), ip)
	_, _ = o.runPS(fmt.Sprintf(`Remove-NetFirewallRule -DisplayName "%s" -ErrorAction SilentlyContinue`, fwAllowRemotesName))
	_, _ = o.runPS(fmt.Sprintf(
		`New-NetFirewallRule -DisplayName "%s" -Group "%s" -Direction Outbound -Action Allow -RemoteAddress %s -ErrorAction SilentlyContinue | Out-Null`,
		fwAllowRemotesName, fwGroup, psStringArray(allow)))
}

// readDefaultOutboundActions returns the current per-profile outbound default
// as "Domain=Allow;Private=Allow;Public=NotConfigured".
func (o *winOS) readDefaultOutboundActions() (string, error) {
	return o.runPS(`((Get-NetFirewallProfile -All | Sort-Object Name |
		ForEach-Object { "$($_.Name)=$($_.DefaultOutboundAction)" }) -join ";")`)
}

// restoreDefaultOutboundActions applies a state string produced by
// readDefaultOutboundActions, one profile at a time.
func (o *winOS) restoreDefaultOutboundActions(state string) {
	for _, part := range strings.Split(state, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			continue
		}
		_, _ = o.runPS(fmt.Sprintf(
			`Set-NetFirewallProfile -Name %s -DefaultOutboundAction %s -ErrorAction SilentlyContinue`,
			kv[0], kv[1]))
	}
}

// readMarkerPriorState returns the prior-state string stashed in the marker
// rule's Description, or "" if no marker exists.
func (o *winOS) readMarkerPriorState() string {
	out, err := o.runPS(fmt.Sprintf(
		`$r = Get-NetFirewallRule -DisplayName "%s" -ErrorAction SilentlyContinue
		if ($r) { $r.Description } else { "" }`, fwMarkerName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// psStringArray renders a Go slice as a PowerShell string-array literal:
// ["a","b"] -> "a","b" (suitable after -RemoteAddress).
func psStringArray(vals []string) string {
	quoted := make([]string, 0, len(vals))
	for _, v := range vals {
		quoted = append(quoted, `"`+v+`"`)
	}
	return strings.Join(quoted, ",")
}
