// Destination-based split tunnelling: decides, per flow, whether a
// destination should egress the physical interface instead of the tunnel.
//
// A "direct" decision only works if the OS route table agrees, and the two
// split-tunnel modes need opposite help from it (routes.go):
//
//   - "exclude" mode captures everything into the tunnel (the split-default
//     route) and dials the bypass set directly, so the bypass set needs
//     *exclusion* routes carving it back out via the physical gateway — the
//     same hazard the coordinator/STUN/TURN exclusions already exist to
//     avoid. Without one, a "direct" dial for a bypass destination would
//     itself get routed straight back into the tunnel adapter by the
//     0.0.0.0/1 + 128.0.0.0/1 split-default routes, re-entering the netstack
//     and looping forever instead of ever reaching the real internet.
//   - "include" mode never installs the split-default at all — the real
//     default route stays authoritative for everything, so "direct" traffic
//     needs no route changes and never even reaches the netstack. Instead the
//     bypass/include set itself needs *inclusion* routes pulling it into the
//     tun adapter, or it would never be captured in the first place (issue
//     #64 — the original implementation only ever added exclusion routes,
//     which in include mode left "direct" meaning "the entire internet," none
//     of it excluded from a split-default that was still being installed).
//
// Static Bypass entries (literal IPs/CIDRs) get their route once, at tunnel
// startup, exactly like the control-plane endpoints. Domain entries can't:
// their IPs aren't known until resolved, and a CDN-backed domain's answer can
// change mid-session. So domains are matched against every DNS query the
// interceptor already sees (tun2socks.go's handleUDP), and each newly-seen
// answer IP is "learned" on the spot — which installs its route (and, if the
// kill-switch is armed, refreshes its allowlist) before the DNS answer is
// handed back to whatever on the device asked for it, so the route exists
// before the follow-up TCP connect can race it. This live-learning path only
// actually fires in exclude mode, though: it depends on the netstack seeing
// *every* DNS query, which is only true when the split-default captures
// everything. In include mode, only already-included destinations' traffic
// reaches the netstack at all, so a domain's mid-session IP rotation isn't
// observed — it keeps its original (possibly now-stale) route from connect
// time. Documented as a known limitation (README), not silently patched over:
// fails toward that one flow going direct/untunnelled, not toward a leak.
//
// "If the kill-switch is armed" has to be answered atomically with respect to
// learn()'s own mutation of the dynamic set (issue #73), or a bypass IP
// learned in the narrow window around arming can end up on neither side of
// that check: not in the kill-switch's initial allowlist (built from a
// snapshot taken before it existed), and not live-refreshed either (armed
// still read as false at the moment onLearn fired). arm() below and learn()
// share one lock for exactly this reason — see arm()'s doc comment.
package enforcement

import (
	"net"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// splitTunnelMode controls how a bypassPolicy's list is interpreted.
type splitTunnelMode string

const (
	// modeExclude (default): listed destinations go direct; everything else
	// is tunnelled. The common case — a short list of sites that must keep
	// the user's real IP.
	modeExclude splitTunnelMode = "exclude"
	// modeInclude: listed destinations are the *only* thing tunnelled;
	// everything else goes direct.
	modeInclude splitTunnelMode = "include"
)

func parseSplitTunnelMode(s string) splitTunnelMode {
	if strings.EqualFold(strings.TrimSpace(s), string(modeInclude)) {
		return modeInclude
	}
	return modeExclude
}

// bypassPolicy decides whether a destination should be dialled directly (out
// the physical interface) or through the tunnel's SOCKS server, and tracks
// which IPs a bypass domain has resolved to so far. It has no PowerShell/OS
// calls of its own — onLearn is how tunnel.go injects the side effects a
// newly-learned IP requires, keeping the matching logic here unit-testable
// on its own.
type bypassPolicy struct {
	mode    splitTunnelMode
	nets    []*net.IPNet // parsed IP/CIDR entries
	domains []string     // lowercase, no trailing dot

	mu      sync.RWMutex
	dynamic map[string]bool // IPs learned by resolving a bypass domain
	armed   bool            // kill-switch armed yet? guarded by mu; set only via arm()

	// onLearn, if set, fires synchronously the first time an IP is added to
	// the dynamic set, with armed reporting whether arm() has already run —
	// read under the same lock as the dynamic-set mutation itself (issue
	// #73), not a separate atomic checked after the fact. tunnel.go wires
	// this to add a route (exclusion or inclusion, depending on mode) and, if
	// armed, refresh the kill-switch's live allowlist.
	onLearn func(ip string, armed bool)
}

// newBypassPolicy classifies each Bypass config entry as a CIDR, a literal
// IP (treated as a /32), or — if neither parses — a domain name.
func newBypassPolicy(mode string, entries []string) *bypassPolicy {
	p := &bypassPolicy{mode: parseSplitTunnelMode(mode), dynamic: map[string]bool{}}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(e); err == nil {
			p.nets = append(p.nets, ipnet)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				p.nets = append(p.nets, &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)})
			}
			continue
		}
		p.domains = append(p.domains, strings.ToLower(strings.TrimSuffix(e, ".")))
	}
	return p
}

// direct reports whether traffic to ip should egress the physical interface
// instead of the tunnel. IPv6 is never "direct" here — it's already dropped
// elsewhere (netstack has no IPv6 route, and the physical adapter's IPv6
// binding is disabled for the tunnel's duration), so it never reaches this
// decision in practice; treating it as "not direct" is just a safe default.
func (p *bypassPolicy) direct(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}
	if p.mode == modeInclude {
		return !p.inSet(ip)
	}
	return p.inSet(ip)
}

// inSet reports whether ip matches a static CIDR/IP entry or a dynamically
// learned bypass-domain address.
func (p *bypassPolicy) inSet(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	p.mu.RLock()
	dyn := p.dynamic[v4.String()]
	p.mu.RUnlock()
	if dyn {
		return true
	}
	for _, n := range p.nets {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

// hasDomains reports whether any Bypass entry is a domain — handleUDP uses
// this to skip parsing DNS packets entirely for the common case where bypass
// is IP/CIDR-only.
func (p *bypassPolicy) hasDomains() bool { return len(p.domains) > 0 }

// observeDNS checks whether query was for one of this policy's bypass
// domains and, if so, learns every A-record address in resp. Called from
// handleUDP for every intercepted DNS exchange; hasDomains keeps it a no-op
// (no parsing at all) for the common case where bypass has no domain
// entries.
func (p *bypassPolicy) observeDNS(query, resp []byte) {
	if !p.hasDomains() {
		return
	}
	name := dnsQuestionName(query)
	if name == "" || !p.matchDomain(name) {
		return
	}
	for _, ip := range dnsAnswerIPs(resp) {
		p.learn(ip)
	}
}

// matchDomain reports whether name (a DNS query's QNAME) is a bypass domain
// or a subdomain of one.
func (p *bypassPolicy) matchDomain(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range p.domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// learn records ip as a dynamically-resolved bypass address and fires
// onLearn the first time it's seen, reporting whether arm() has already run.
// Safe to call from multiple goroutines (one handleUDP flow per intercepted
// UDP "connection") and safe to race against a concurrent arm() call: both
// take the same lock, so whichever runs first completes entirely (dynamic
// mutated and armed read, or snapshot taken and armed flipped) before the
// other proceeds — see arm()'s doc comment for why that matters.
func (p *bypassPolicy) learn(ip net.IP) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	key := v4.String()
	p.mu.Lock()
	if p.dynamic[key] {
		p.mu.Unlock()
		return
	}
	p.dynamic[key] = true
	armed := p.armed
	p.mu.Unlock()
	if p.onLearn != nil {
		p.onLearn(key, armed)
	}
}

// arm marks the policy as kill-switch-armed and, atomically with respect to
// learn(), passes install a snapshot of the dynamic set at the exact moment
// armed flips true. install is tunnel.go's kill-switch-enable call — it runs
// while the lock is still held, so no learn() call can land between "the
// snapshot install() sees" and "armed becomes true": either learn() acquires
// the lock first (its IP lands in this snapshot, since it's already in
// p.dynamic by the time arm() can read it) or arm() acquires it first (that
// learn() call, once it gets the lock, observes armed already true and fires
// onLearn's live-refresh path instead). Every learned IP ends up on exactly
// one of those two paths — never neither, which was issue #73: a snapshot
// read and an armed flip that weren't synchronized against learn() at all
// could both miss the same IP.
//
// Holding the lock for install's whole duration — in practice a PowerShell
// shell-out (enableKillSwitch's several New-NetFirewallRule calls) — stalls
// any concurrent learn() (and briefly inSet()/direct(), since a pending
// writer blocks new readers on sync.RWMutex) for however long that takes.
// Acceptable: this runs once, at connect, and DNS's own read deadline in
// handleUDP (tun2socks.go) is 10s — far longer than a handful of PowerShell
// calls take.
func (p *bypassPolicy) arm(install func(dynamicSnapshot []string) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	snapshot := make([]string, 0, len(p.dynamic))
	for ip := range p.dynamic {
		snapshot = append(snapshot, ip)
	}
	if err := install(snapshot); err != nil {
		return err
	}
	p.armed = true
	return nil
}

// seed pre-populates the dynamic set without firing onLearn. Used once at
// tunnel startup (tunnel.go) for a domain's already-resolved address, where
// the caller is folding the result into its own startup route/allowlist
// batch rather than wanting a one-off callback per address.
func (p *bypassPolicy) seed(ip net.IP) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	p.mu.Lock()
	p.dynamic[v4.String()] = true
	p.mu.Unlock()
}

// resolveDomains resolves each domain via the OS's own resolver and returns
// every IPv4 address found across all of them. Unresolvable domains are
// skipped — best effort, same posture as routes.go's resolveExclusions.
// Safe to call for bypass domains specifically: they're explicitly meant to
// be reached with the real IP, not hidden behind the tunnel, so resolving
// them outside it leaks nothing that bypass wasn't already going to expose.
func resolveDomains(domains []string) []net.IP {
	var ips []net.IP
	for _, d := range domains {
		addrs, err := net.LookupHost(d)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// staticEntries returns the CIDR/IP prefixes that must get a route (exclusion
// in "exclude" mode, inclusion in "include" mode — tunnel.go decides which)
// at startup — every parsed non-domain Bypass entry. Domain entries are
// handled live via learn() instead, since their IPs aren't known until the
// DNS interceptor resolves them.
func (p *bypassPolicy) staticEntries() []string {
	out := make([]string, 0, len(p.nets))
	for _, n := range p.nets {
		out = append(out, n.String())
	}
	return out
}

// dynamicSnapshot returns every IP learned so far, for teardown cleanup.
func (p *bypassPolicy) dynamicSnapshot() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.dynamic))
	for ip := range p.dynamic {
		out = append(out, ip)
	}
	return out
}

// dnsQuestionName returns the QNAME of a DNS query message, or "" if it
// can't be parsed. Best-effort by design: split tunnelling is a bonus on top
// of DNS resolution, never something that should be allowed to break it.
func dnsQuestionName(query []byte) string {
	var parser dnsmessage.Parser
	if _, err := parser.Start(query); err != nil {
		return ""
	}
	q, err := parser.Question()
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(q.Name.String(), ".")
}

// dnsAnswerIPs returns the A-record addresses in a DNS response, in order.
func dnsAnswerIPs(resp []byte) []net.IP {
	var parser dnsmessage.Parser
	if _, err := parser.Start(resp); err != nil {
		return nil
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil
	}
	var ips []net.IP
	for {
		h, err := parser.AnswerHeader()
		if err != nil {
			return ips // includes the normal end-of-section error
		}
		if h.Type != dnsmessage.TypeA {
			if err := parser.SkipAnswer(); err != nil {
				return ips
			}
			continue
		}
		r, err := parser.AResource()
		if err != nil {
			return ips
		}
		ips = append(ips, net.IP(r.A[:]))
	}
}
