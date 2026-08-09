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
//     tun adapter, or it would never be captured in the first place
//     (old #64 — the original implementation only ever added exclusion routes,
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
// learn()'s own mutation of the dynamic set (old #73), or a bypass IP
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

	// problems is one sentence per configured entry this policy could not make
	// use of (bacchus#258). startTunnel logs them at every connect, which is the
	// point: an entry the user can see in their own config file, and which does
	// nothing, is worse than one refused out loud — they read the file and
	// reasonably conclude the hole is punched.
	problems []string

	mu      sync.RWMutex
	dynamic map[string]bool // IPs learned by resolving a bypass domain
	armed   bool            // kill-switch armed yet? guarded by mu; set only via arm()

	// onLearn, if set, fires synchronously the first time an IP is added to
	// the dynamic set, with armed reporting whether arm() has already run —
	// read under the same lock as the dynamic-set mutation itself
	// (old #73), not a separate atomic checked after the fact. tunnel.go wires
	// this to add a route (exclusion or inclusion, depending on mode) and, if
	// armed, refresh the kill-switch's live allowlist.
	onLearn func(ip string, armed bool)
}

// newBypassPolicy classifies each Bypass config entry as a CIDR, a literal
// IP (treated as a /32), or — if neither parses — a domain name.
//
// Every entry it cannot honour is recorded in problems, and NONE is dropped in
// silence (bacchus#258). See classifyBypassEntry for what "cannot honour" means
// and why the alternative — accept, store, display and ignore — is the one
// option this package will not take.
func newBypassPolicy(mode string, entries []string) *bypassPolicy {
	p := &bypassPolicy{mode: parseSplitTunnelMode(mode), dynamic: map[string]bool{}}
	for _, e := range entries {
		switch c := classifyBypassEntry(e); c.kind {
		case bypassPrefix:
			p.nets = append(p.nets, c.prefix)
		case bypassDomain:
			p.domains = append(p.domains, c.name)
		case bypassUnusable:
			p.problems = append(p.problems, c.problem)
		}
	}
	return p
}

// bypassKind is what one Bypass entry turned out to be.
type bypassKind int

const (
	// bypassBlank: an empty or whitespace-only line. Not a problem — the
	// settings window's multi-line entry produces them freely.
	bypassBlank bypassKind = iota
	// bypassPrefix: an IPv4 network prefix, or a bare IPv4 address normalised
	// to a /32 host prefix. These get a route at connect and an entry in the
	// kill-switch allowlist.
	bypassPrefix
	// bypassDomain: a host name, matched against the DNS the interceptor sees
	// and resolved once at connect.
	bypassDomain
	// bypassUnusable: none of the above. The entry is reported and ignored,
	// rather than only ignored.
	bypassUnusable
)

// classifiedBypass is one entry's verdict: exactly one of prefix, name and
// problem is set, chosen by kind.
type classifiedBypass struct {
	kind    bypassKind
	prefix  *net.IPNet // bypassPrefix
	name    string     // bypassDomain: lowercase, no trailing dot
	problem string     // bypassUnusable: one sentence naming the entry
}

// classifyBypassEntry decides what one Bypass entry is, and — when it is
// nothing this client can act on — says so in a sentence naming the entry.
//
// It is the single definition of what a bypass entry may be, shared by
// newBypassPolicy (which builds the live policy from it) and CheckBypass (which
// reports on a config before anything connects). Two copies of these rules would
// be two answers to "is this entry in force", and the one that reaches the user
// would be the one that is wrong.
//
// # What is refused, and why refusing beats ignoring
//
// bacchus#258 measured a CIDR added to `bypass` producing a firewall rule
// byte-identical to the one before it. Prefixes are in fact honoured here and
// have been since the enforcement fold — but three shapes were not, and each was
// dropped without a word:
//
//   - An IPv6 address or prefix. It parsed, and then fell off the end of a
//     v4-only path: the netstack has no IPv6 route, disablePhysicalIPv6 turns the
//     physical adapter's IPv6 off for the tunnel's duration, and inSet answers
//     false for every v6 address regardless. Refused with that reason rather
//     than accepted into a set nothing consults.
//   - A MALFORMED prefix — `192.0.2.0/33`, `192.0.2.0/255.255.255.0`, a
//     backslash for a slash. ParseCIDR refuses it, ParseIP refuses it, and it
//     then became a "domain": a name that resolves to nothing, forever, in
//     silence. An entry containing a slash is unambiguously meant as a prefix,
//     so it is reported as a broken one instead of quietly reinterpreted as
//     something else.
//   - An entry that is not a usable host name — a space in it, an empty label,
//     a label of only digits (`192.0.2`, an address one octet short). The
//     last is the sharpest: it looks like an address to the person who typed it
//     and like a name to the resolver, so it can only ever fail.
//
// A host name that is well-formed but does not resolve is NOT refused here. That
// is not a property of the config — a name can be unresolvable at this moment and
// fine at the next connect — so it is reported at connect instead, by the
// resolution that actually failed (resolveDomains).
func classifyBypassEntry(entry string) classifiedBypass {
	unusable := func(why string) classifiedBypass {
		return classifiedBypass{kind: bypassUnusable, problem: quoteEntry(strings.TrimSpace(entry)) + " " + why}
	}
	const noIPv6 = "and Bacchus carries IPv4 only and turns IPv6 off while connected, so it is ignored"

	e := strings.TrimSpace(entry)
	if e == "" {
		return classifiedBypass{kind: bypassBlank}
	}
	if _, ipnet, err := net.ParseCIDR(e); err == nil {
		if ipnet.IP.To4() == nil {
			return unusable("is an IPv6 network, " + noIPv6)
		}
		return classifiedBypass{kind: bypassPrefix, prefix: ipnet}
	}
	if ip := net.ParseIP(e); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return unusable("is an IPv6 address, " + noIPv6)
		}
		return classifiedBypass{kind: bypassPrefix, prefix: &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}}
	}
	if strings.ContainsAny(e, `/\`) {
		return unusable("is not a network prefix Bacchus can read — write one like 192.0.2.0/24 — so it is ignored")
	}
	name := strings.ToLower(strings.TrimSuffix(e, "."))
	if !isHostName(name) {
		return unusable("is not a host name, an address or a network prefix like 192.0.2.0/24, so it is ignored")
	}
	return classifiedBypass{kind: bypassDomain, name: name}
}

// isHostName reports whether name can be looked up as a host name at all:
// dot-separated labels of letters, digits and hyphens, none empty, none longer
// than 63 bytes, none starting or ending in a hyphen, 253 bytes in total.
//
// A name whose every label is digits is refused, and that case is the reason
// this is stricter than "the resolver would accept it". `192.0.2` is an
// address a user typed one octet short: it cannot parse as an address and it
// cannot resolve as a name, so the only two outcomes are "reported" and
// "silently does nothing".
func isHostName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	allNumeric := true
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
				allNumeric = false
			case c >= '0' && c <= '9':
			case c == '-':
				allNumeric = false
			default:
				return false
			}
		}
	}
	return !allNumeric
}

// quoteEntry renders one config entry inside a sentence. Quoted so a value with
// a space, or an empty-looking one, is visible as itself.
func quoteEntry(e string) string { return `"` + e + `"` }

// CheckBypass reports every `bypass` entry this client cannot act on, one
// sentence each, in the order they appear. An empty result means every entry is
// in force.
//
// Exported for the client's own startup check (appstate.CheckConfig): the point
// of bacchus#258 is that the user is told BEFORE they rely on an entry, not that
// the log records it afterwards. It runs the same classifier the live policy is
// built from, so what it reports and what is installed cannot drift apart.
func CheckBypass(entries []string) []string {
	var problems []string
	for _, e := range entries {
		if c := classifyBypassEntry(e); c.kind == bypassUnusable {
			problems = append(problems, c.problem)
		}
	}
	return problems
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
// one of those two paths — never neither, which was old #73: a snapshot
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
// every IPv4 address found across all of them, plus the names that yielded
// none. Unresolvable domains are still skipped — best effort, same posture as
// routes.go's resolveExclusions — but they are no longer skipped in SILENCE:
// startTunnel names them in the log (bacchus#258), because a bypass entry that
// resolves to nothing is a hole the user believes they punched and did not.
//
// Safe to call for bypass domains specifically: they're explicitly meant to
// be reached with the real IP, not hidden behind the tunnel, so resolving
// them outside it leaks nothing that bypass wasn't already going to expose.
//
// A name is reported when it produced no IPv4 address, which is not the same as
// "the lookup returned an error": a name with only AAAA records resolves fine
// and is still unusable here, for the reason classifyBypassEntry refuses an IPv6
// literal outright.
// lookupHost is net.LookupHost behind a variable so a test can drive the
// reporting path above without a resolver, a network, or a name whose failure
// mode depends on the machine's DNS configuration. Production never replaces it.
var lookupHost = net.LookupHost

func resolveDomains(domains []string) (ips []net.IP, unresolved []string) {
	for _, d := range domains {
		before := len(ips)
		addrs, err := lookupHost(d)
		if err == nil {
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
					ips = append(ips, ip)
				}
			}
		}
		if len(ips) == before {
			unresolved = append(unresolved, d)
		}
	}
	return ips, unresolved
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
