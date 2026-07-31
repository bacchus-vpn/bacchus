//go:build linux

// The kill-switch against a real kernel. Assertions read `nft list ruleset` —
// nftables' own renderer, a completely independent implementation from the
// message encoder under test — so a shared misunderstanding between the code
// that writes the rules and the code that checks them is not possible.
package main

import (
	"net/netip"
	"strings"
	"testing"
)

func armFixture(t *testing.T) (*nftConn, killSwitchSpec) {
	t.Helper()
	fixtureUplink(t)
	ipCmd(t, "link", "add", "bacchus0", "type", "dummy")
	ipCmd(t, "link", "set", "bacchus0", "up")

	c, err := dialNftables()
	if err != nil {
		t.Fatalf("dialNftables: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	return c, killSwitchSpec{
		TunIfIndex: mustIfIndex(t, "bacchus0"),
		LoIfIndex:  mustIfIndex(t, "lo"),
		Hosts: []netip.Addr{
			netip.MustParseAddr("192.0.2.50"), // a coordinator
			netip.MustParseAddr("198.51.100.9"),
		},
		Nets: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
	}
}

func TestKillSwitchArmsAsOneDropPolicyChain(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c, spec := armFixture(t)

	if err := c.enableKillSwitch(spec); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}

	out := nftCmd(t, "list", "ruleset")
	t.Logf("ruleset:\n%s", out)

	// The default action is what makes this fail-closed. Everything else in
	// the chain is an exception to it.
	if !strings.Contains(out, "table inet bacchus") {
		t.Errorf("our table is missing:\n%s", out)
	}
	if !strings.Contains(out, "policy drop") {
		t.Errorf("chain policy is not drop — the lockdown would leak:\n%s", out)
	}
	if !strings.Contains(out, "type filter hook output") {
		t.Errorf("chain is not on the output hook:\n%s", out)
	}

	// Asserted against nft's IDIOMATIC rendering, not merely against the
	// addresses appearing somewhere. This is the assertion that has teeth: a
	// wrong meta key is a valid comparison against the wrong thing, so the
	// kernel accepts it and the transaction succeeds. NFT_META_OIF mistyped as
	// NFT_META_OIFNAME rendered `oifname ""` — a rule matching nothing, in a
	// chain whose policy is drop, which would have blocked all tunnelled
	// traffic while every "did it arm?" check still passed.
	for _, want := range []string{
		`set allow4 {`,
		`type ipv4_addr`,
		`oif "bacchus0" accept`, // the tunnel adapter, by index, not by name
		`ip daddr @allow4 accept`,
		`ip daddr 203.0.113.0/24 accept`,
		`udp sport 68 udp dport 67 accept`,
		`192.0.2.50`,
		`198.51.100.9`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset is missing %q:\n%s", want, out)
		}
	}
	// Nothing should have rendered as a raw payload expression: that is what
	// nft prints when it cannot recognise the idiom, and it means an operand
	// is not what it was meant to be.
	if strings.Contains(out, "@nh,") || strings.Contains(out, "iiftype") {
		t.Errorf("a rule did not encode to the intended idiom:\n%s", out)
	}
}

// ADR-0049 §8: adding a late-learned bypass address must be an atomic element
// addition that touches no rule. This asserts the "touches no rule" half
// directly — the rule text before and after must be byte-identical — because
// that is what distinguishes it from the Windows remove-and-recreate, and a
// reimplementation that rebuilt the rule would still pass a test that only
// checked the address was present afterwards.
func TestRefreshAllowIPAddsAnElementWithoutRebuildingRules(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c, spec := armFixture(t)
	if err := c.enableKillSwitch(spec); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}

	rulesBefore := nftCmd(t, "list", "chain", "inet", "bacchus", "output")

	learned := netip.MustParseAddr("198.51.100.200")
	if err := c.refreshAllowIP(learned); err != nil {
		t.Fatalf("refreshAllowIP: %v", err)
	}

	out := nftCmd(t, "list", "ruleset")
	if !strings.Contains(out, "198.51.100.200") {
		t.Errorf("learned address did not reach the allowlist:\n%s", out)
	}

	rulesAfter := nftCmd(t, "list", "chain", "inet", "bacchus", "output")
	if rulesBefore != rulesAfter {
		t.Errorf("the rules changed, so there was a window where the allowlist was not in force.\nbefore:\n%s\nafter:\n%s", rulesBefore, rulesAfter)
	}

	// Re-learning the same address is the normal case (a domain resolving to
	// an address already seen) and must not be an error.
	if err := c.refreshAllowIP(learned); err != nil {
		t.Fatalf("re-adding a known address must be a no-op, got: %v", err)
	}
}

// Parity item 3. The helper reaps its own orphan, and "its own" is answerable
// by name here rather than by the heuristic Windows needs.
func TestRecoverLiftsOurOwnStaleLockdown(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c, spec := armFixture(t)

	if exists, err := c.tableExists(); err != nil || exists {
		t.Fatalf("tableExists before arming = %v, %v; want false, nil", exists, err)
	}
	if err := c.enableKillSwitch(spec); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}
	exists, err := c.tableExists()
	if err != nil {
		t.Fatalf("tableExists: %v", err)
	}
	if !exists {
		t.Fatal("tableExists after arming = false, want true")
	}

	if err := c.deleteTable(); err != nil {
		t.Fatalf("deleteTable: %v", err)
	}
	if out := nftCmd(t, "list", "ruleset"); strings.Contains(out, "table inet bacchus") {
		t.Errorf("our table survived the lift:\n%s", out)
	}
	// Idempotent: lifting a lockdown that is not armed is a no-op, which is
	// what lets Recover() run unconditionally at every launch.
	if err := c.deleteTable(); err != nil {
		t.Fatalf("second deleteTable must be a no-op, got: %v", err)
	}
}

// A lockdown must not touch firewall state that is not ours. A distribution
// ships its own nftables rules, and another VPN may have its own table; tearing
// those down on disconnect would be a far worse failure than not arming at all.
func TestLiftingLeavesOtherTablesAlone(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c, spec := armFixture(t)

	nftCmd(t, "add", "table", "inet", "somebody-else")
	nftCmd(t, "add", "chain", "inet", "somebody-else", "forward",
		"{ type filter hook forward priority 0; policy accept; }")

	if err := c.enableKillSwitch(spec); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}
	if err := c.deleteTable(); err != nil {
		t.Fatalf("deleteTable: %v", err)
	}

	out := nftCmd(t, "list", "ruleset")
	if !strings.Contains(out, "somebody-else") {
		t.Errorf("we deleted another table's state:\n%s", out)
	}
	if strings.Contains(out, "table inet bacchus") {
		t.Errorf("our own table survived:\n%s", out)
	}
}

// Arming twice in a row must converge rather than fail: Start runs Recover
// defensively before arming, and a reconnect after an unclean teardown lands
// here.
func TestArmingOverAnExistingLockdownConverges(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c, spec := armFixture(t)

	if err := c.enableKillSwitch(spec); err != nil {
		t.Fatalf("first enableKillSwitch: %v", err)
	}
	if err := c.deleteTable(); err != nil {
		t.Fatalf("deleteTable: %v", err)
	}
	if err := c.enableKillSwitch(spec); err != nil {
		t.Fatalf("second enableKillSwitch: %v", err)
	}
	out := nftCmd(t, "list", "ruleset")
	if !strings.Contains(out, "policy drop") {
		t.Errorf("re-armed lockdown is not fail-closed:\n%s", out)
	}
}
