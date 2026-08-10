package enforcement

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNewBypassPolicyClassifiesEntries(t *testing.T) {
	p := newBypassPolicy("", []string{
		" 1.2.3.4 ", "10.0.0.0/8", "sberbank.ru", "www.Gosuslugi.RU.", "", "  ",
	})
	if got, want := len(p.nets), 2; got != want {
		t.Fatalf("len(nets) = %d, want %d", got, want)
	}
	if got, want := p.domains, []string{"sberbank.ru", "www.gosuslugi.ru"}; !equalStrings(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
	if !p.inSet(net.ParseIP("1.2.3.4")) {
		t.Error("1.2.3.4 should match its literal /32")
	}
	if !p.inSet(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 should match 10.0.0.0/8")
	}
	if p.inSet(net.ParseIP("11.1.2.3")) {
		t.Error("11.1.2.3 should not match any entry")
	}
}

// ---------------------------------------------------------------------------
// A bypass entry is honoured or it is reported — never neither (bacchus#258)
// ---------------------------------------------------------------------------

// TestABypassPrefixIsCarriedToTheRoutesAndTheAllowlist is bacchus#258's own
// scenario, in the shape it was measured in: the ten host names the shipped
// example config carries, plus one range added by hand. The card reports the
// resulting firewall rule as byte-identical to the one before — no prefix in it
// anywhere — so this asserts the prefix reaches the two places that consume it.
//
// staticEntries is what tunnel.go hands to addExclusionRoutes AND, appended to
// the resolved dynamic set, to enableKillSwitch. There is no third path, so a
// prefix present here is a prefix in force.
//
// Mutation check: delete the ParseCIDR branch in classifyBypassEntry and this
// fails, reporting exactly what the card measured — the ten names and nothing
// else.
func TestABypassPrefixIsCarriedToTheRoutesAndTheAllowlist(t *testing.T) {
	entries := []string{
		"sberbank.ru", "gosuslugi.ru", "nalog.gov.ru", "gov.ru", "vk.com",
		"ok.ru", "yandex.ru", "kinopoisk.ru", "ivi.ru", "rutube.ru",
		"100.64.0.0/10",
	}
	p := newBypassPolicy("exclude", entries)

	if got, want := len(p.domains), 10; got != want {
		t.Fatalf("domains = %d, want %d", got, want)
	}
	if got, want := p.staticEntries(), []string{"100.64.0.0/10"}; !equalStrings(got, want) {
		t.Fatalf("staticEntries = %v, want %v — the range is not in force", got, want)
	}
	if len(p.problems) != 0 {
		t.Fatalf("problems = %v, want none: every entry here is usable", p.problems)
	}
	// And it decides traffic, which is the point of the route: an address inside
	// the range goes direct rather than into the tunnel.
	if !p.direct(net.ParseIP("100.100.1.1")) {
		t.Error("an address inside the configured range is not treated as direct")
	}
}

// TestEveryUnusableBypassEntryIsNamed covers the three shapes that used to be
// dropped in silence. Accept-and-ignore is the one option bacchus#258 calls
// indefensible, and each of these was it.
//
// Mutation check: return bypassDomain instead of bypassUnusable for any row and
// this names that row.
func TestEveryUnusableBypassEntryIsNamed(t *testing.T) {
	cases := []struct {
		entry string
		why   string
	}{
		{"2001:db8::/32", "an IPv6 prefix: parsed fine, then fell off a v4-only path"},
		{"2001:db8::1", "an IPv6 literal: ParseIP succeeded and To4() did not, so it was skipped entirely"},
		{"203.0.113.0/33", "a prefix length that does not exist"},
		{"203.0.113.0/255.255.255.0", "a netmask where a prefix length goes"},
		{`203.0.113.0\24`, "a backslash for a slash"},
		{"192.0.2", "an address one octet short — a name to the resolver, an address to the person who typed it"},
		{"not a host name", "spaces"},
		{"-example.com", "a label starting with a hyphen"},
		{"example..com", "an empty label"},
	}
	for _, c := range cases {
		t.Run(c.entry, func(t *testing.T) {
			p := newBypassPolicy("exclude", []string{c.entry})
			if len(p.nets) != 0 || len(p.domains) != 0 {
				t.Fatalf("%q was accepted as nets=%v domains=%v; this test is about entries that are NOT honoured", c.entry, p.nets, p.domains)
			}
			if len(p.problems) != 1 {
				t.Fatalf("%q (%s) produced %d problems, want 1 — it is dropped in silence", c.entry, c.why, len(p.problems))
			}
			if !strings.Contains(p.problems[0], c.entry) {
				t.Errorf("problem %q does not name the entry it is about", p.problems[0])
			}
		})
	}
}

// TestCheckBypassCannotDisagreeWithTheLivePolicy is the anti-drift check, and it
// is the reason CheckBypass and newBypassPolicy share one classifier rather than
// each having its own rules.
//
// Two copies of "what may a bypass entry be" would be two answers to "is this
// entry in force", and the one the user reads would be the one that is wrong —
// which is bacchus#258 again, one level up. So: for every entry, the reporter
// says there is a problem if and only if the live policy dropped it.
//
// Mutation check: add a case to classifyBypassEntry that CheckBypass filters
// differently from newBypassPolicy and this fails, naming the entry.
func TestCheckBypassCannotDisagreeWithTheLivePolicy(t *testing.T) {
	entries := []string{
		"example.com", "192.0.2.0/24", "198.51.100.7", "  ", "",
		"2001:db8::/32", "2001:db8::1", "203.0.113.0/33", `203.0.113.0\24`,
		"192.0.2", "not a host name", "localhost", "WWW.Example.COM.",
	}
	reported := map[string]bool{}
	for _, e := range entries {
		if len(CheckBypass([]string{e})) > 0 {
			reported[e] = true
		}
	}
	for _, e := range entries {
		p := newBypassPolicy("exclude", []string{e})
		dropped := len(p.nets) == 0 && len(p.domains) == 0 && strings.TrimSpace(e) != ""
		if dropped != reported[e] {
			t.Errorf("%q: the live policy dropped it = %v, CheckBypass reports a problem = %v — the report and the behaviour disagree",
				e, dropped, reported[e])
		}
	}
	// And the whole list at once reports each unusable entry exactly once, in
	// order, which is what main.go puts on the detail line.
	if got, want := len(CheckBypass(entries)), 6; got != want {
		t.Fatalf("CheckBypass over the whole list = %d findings, want %d", got, want)
	}
}

// TestResolveDomainsNamesWhatResolvedToNothing is the other half of the same
// silence: an entry whose SHAPE is fine and which produces no address is still a
// hole the user believes they punched. It was skipped by a bare `continue`.
//
// A name with only AAAA records counts as unresolved here, deliberately: this
// client carries IPv4 only, so such a name is exactly as unusable as one that
// does not resolve at all, and reporting it is the honest answer.
func TestResolveDomainsNamesWhatResolvedToNothing(t *testing.T) {
	answers := map[string][]string{
		"good.example":   {"192.0.2.7"},
		"v6only.example": {"2001:db8::1"},
	}
	prev := lookupHost
	lookupHost = func(host string) ([]string, error) {
		if a, ok := answers[host]; ok {
			return a, nil
		}
		return nil, fmt.Errorf("no such host %q", host)
	}
	t.Cleanup(func() { lookupHost = prev })

	ips, unresolved := resolveDomains([]string{"good.example", "v6only.example", "gone.example"})
	if len(ips) != 1 || ips[0].String() != "192.0.2.7" {
		t.Fatalf("ips = %v, want the one IPv4 answer", ips)
	}
	if got, want := unresolved, []string{"v6only.example", "gone.example"}; !equalStrings(got, want) {
		t.Fatalf("unresolved = %v, want %v", got, want)
	}
}

func TestParseSplitTunnelMode(t *testing.T) {
	cases := map[string]splitTunnelMode{
		"":         modeExclude,
		"exclude":  modeExclude,
		"bogus":    modeExclude,
		"include":  modeInclude,
		" Include": modeInclude,
	}
	for in, want := range cases {
		if got := parseSplitTunnelMode(in); got != want {
			t.Errorf("parseSplitTunnelMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBypassPolicyDirectExcludeMode(t *testing.T) {
	p := newBypassPolicy("exclude", []string{"1.2.3.4"})
	if !p.direct(net.ParseIP("1.2.3.4")) {
		t.Error("listed entry should go direct in exclude mode")
	}
	if p.direct(net.ParseIP("9.9.9.9")) {
		t.Error("unlisted entry should tunnel in exclude mode")
	}
}

func TestBypassPolicyDirectIncludeMode(t *testing.T) {
	p := newBypassPolicy("include", []string{"1.2.3.4"})
	if p.direct(net.ParseIP("1.2.3.4")) {
		t.Error("listed entry should tunnel in include mode")
	}
	if !p.direct(net.ParseIP("9.9.9.9")) {
		t.Error("unlisted entry should go direct in include mode")
	}
}

func TestBypassPolicyDirectNeverIPv6(t *testing.T) {
	p := newBypassPolicy("include", nil) // include mode: everything not listed is direct
	if p.direct(net.ParseIP("2001:db8::1")) {
		t.Error("IPv6 should never be treated as direct")
	}
}

func TestBypassPolicyMatchDomainSuffix(t *testing.T) {
	p := newBypassPolicy("", []string{"bank.ru"})
	for _, name := range []string{"bank.ru", "bank.ru.", "www.bank.ru", "BANK.RU"} {
		if !p.matchDomain(name) {
			t.Errorf("matchDomain(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"notbank.ru", "bank.ru.evil.example"} {
		if p.matchDomain(name) {
			t.Errorf("matchDomain(%q) = true, want false", name)
		}
	}
}

func TestBypassPolicyLearnFiresOnLearnOnce(t *testing.T) {
	p := newBypassPolicy("", nil)
	var learned []string
	p.onLearn = func(ip string, armed bool) { learned = append(learned, ip) }

	ip := net.ParseIP("5.6.7.8")
	p.learn(ip)
	p.learn(ip) // second call for the same IP must not fire onLearn again

	if !equalStrings(learned, []string{"5.6.7.8"}) {
		t.Fatalf("onLearn calls = %v, want a single call for 5.6.7.8", learned)
	}
	if !p.inSet(ip) {
		t.Error("learned IP should be in the set")
	}
}

func TestBypassPolicySeedDoesNotFireOnLearn(t *testing.T) {
	p := newBypassPolicy("", nil)
	fired := false
	p.onLearn = func(string, bool) { fired = true }

	p.seed(net.ParseIP("5.6.7.8"))

	if fired {
		t.Error("seed should not fire onLearn")
	}
	if !p.inSet(net.ParseIP("5.6.7.8")) {
		t.Error("seeded IP should be in the set")
	}
}

func TestBypassPolicyLearnReportsArmedFalseBeforeArm(t *testing.T) {
	p := newBypassPolicy("", nil)
	var gotArmed bool
	var called bool
	p.onLearn = func(ip string, armed bool) { called = true; gotArmed = armed }

	p.learn(net.ParseIP("5.6.7.8"))

	if !called {
		t.Fatal("onLearn was not called")
	}
	if gotArmed {
		t.Error("onLearn should report armed=false before arm() has run")
	}
}

func TestBypassPolicyLearnReportsArmedTrueAfterArm(t *testing.T) {
	p := newBypassPolicy("", nil)
	if err := p.arm(func([]string) error { return nil }); err != nil {
		t.Fatalf("arm() error: %v", err)
	}

	var gotArmed bool
	p.onLearn = func(ip string, armed bool) { gotArmed = armed }
	p.learn(net.ParseIP("5.6.7.8"))

	if !gotArmed {
		t.Error("onLearn should report armed=true once arm() has already run")
	}
}

func TestBypassPolicyArmSnapshotIncludesPriorLearns(t *testing.T) {
	p := newBypassPolicy("", nil)
	p.seed(net.ParseIP("1.1.1.1"))
	p.learn(net.ParseIP("2.2.2.2"))

	var snapshot []string
	if err := p.arm(func(dynamicSnapshot []string) error {
		snapshot = dynamicSnapshot
		return nil
	}); err != nil {
		t.Fatalf("arm() error: %v", err)
	}

	want := map[string]bool{"1.1.1.1": true, "2.2.2.2": true}
	if len(snapshot) != len(want) {
		t.Fatalf("arm() snapshot = %v, want keys %v", snapshot, want)
	}
	for _, ip := range snapshot {
		if !want[ip] {
			t.Errorf("unexpected ip %q in arm() snapshot", ip)
		}
	}
}

func TestBypassPolicyArmPropagatesInstallErrorAndStaysUnarmed(t *testing.T) {
	p := newBypassPolicy("", nil)
	installErr := fmt.Errorf("boom")

	err := p.arm(func([]string) error { return installErr })
	if err != installErr {
		t.Fatalf("arm() error = %v, want %v", err, installErr)
	}

	var gotArmed bool
	p.onLearn = func(ip string, armed bool) { gotArmed = armed }
	p.learn(net.ParseIP("5.6.7.8"))
	if gotArmed {
		t.Error("a failed arm() must not leave the policy armed")
	}
}

// TestBypassPolicyArmLearnRaceNeverLosesAnIP is the regression test for
// old #73: a bypass IP learned concurrently with arm() must always end up on at
// least one side of the ordering — baked into arm()'s snapshot, or reported
// live via onLearn(ip, true) — never neither. The bug this guards against was
// exactly a window where an IP could land on neither side, because the old
// design read/wrote the "armed" state through a separate atomic.Bool with no
// coordination against the dynamic-set's own lock. Runs many trials since a
// timing race isn't guaranteed to reproduce on a single attempt.
func TestBypassPolicyArmLearnRaceNeverLosesAnIP(t *testing.T) {
	const trials = 200
	const ips = 20
	for trial := 0; trial < trials; trial++ {
		p := newBypassPolicy("", nil)

		var mu sync.Mutex
		liveRefreshed := map[string]bool{}
		p.onLearn = func(ip string, armed bool) {
			if armed {
				mu.Lock()
				liveRefreshed[ip] = true
				mu.Unlock()
			}
		}

		var snapshot []string
		var wg sync.WaitGroup
		wg.Add(ips + 1)
		for i := 0; i < ips; i++ {
			ip := fmt.Sprintf("10.0.%d.%d", trial%256, i)
			go func() {
				defer wg.Done()
				p.learn(net.ParseIP(ip))
			}()
		}
		go func() {
			defer wg.Done()
			_ = p.arm(func(dynamicSnapshot []string) error {
				snapshot = dynamicSnapshot
				return nil
			})
		}()
		wg.Wait()

		inSnapshot := map[string]bool{}
		for _, ip := range snapshot {
			inSnapshot[ip] = true
		}
		for i := 0; i < ips; i++ {
			ip := fmt.Sprintf("10.0.%d.%d", trial%256, i)
			if !inSnapshot[ip] && !liveRefreshed[ip] {
				t.Fatalf("trial %d: ip %s landed on neither arm() snapshot nor a live armed=true refresh", trial, ip)
			}
		}
	}
}

func TestBypassPolicyDynamicSnapshot(t *testing.T) {
	p := newBypassPolicy("", nil)
	p.seed(net.ParseIP("1.1.1.1"))
	p.learn(net.ParseIP("2.2.2.2"))
	got := p.dynamicSnapshot()
	want := map[string]bool{"1.1.1.1": true, "2.2.2.2": true}
	if len(got) != len(want) {
		t.Fatalf("dynamicSnapshot = %v, want keys %v", got, want)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Errorf("unexpected ip %q in snapshot", ip)
		}
	}
}

func TestBypassPolicyStaticEntries(t *testing.T) {
	p := newBypassPolicy("", []string{"1.2.3.4", "10.0.0.0/8", "example.ru"})
	got := p.staticEntries()
	want := map[string]bool{"1.2.3.4/32": true, "10.0.0.0/8": true}
	if len(got) != len(want) {
		t.Fatalf("staticEntries = %v, want %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected prefix %q", p)
		}
	}
}

func TestObserveDNSSkipsNonBypassDomains(t *testing.T) {
	p := newBypassPolicy("", []string{"bank.ru"})
	var learned []string
	p.onLearn = func(ip string, armed bool) { learned = append(learned, ip) }

	query := buildDNSQuery(t, "example.com.")
	resp := buildDNSAnswer(t, "example.com.", [4]byte{9, 9, 9, 9})
	p.observeDNS(query, resp)

	if len(learned) != 0 {
		t.Fatalf("observeDNS learned %v for a non-bypass domain, want none", learned)
	}
}

func TestObserveDNSLearnsBypassDomainAnswers(t *testing.T) {
	p := newBypassPolicy("", []string{"bank.ru"})
	var learned []string
	p.onLearn = func(ip string, armed bool) { learned = append(learned, ip) }

	query := buildDNSQuery(t, "www.bank.ru.")
	resp := buildDNSAnswer(t, "www.bank.ru.", [4]byte{1, 2, 3, 4}, [4]byte{1, 2, 3, 5})
	p.observeDNS(query, resp)

	want := []string{"1.2.3.4", "1.2.3.5"}
	if !equalStrings(learned, want) {
		t.Fatalf("learned = %v, want %v", learned, want)
	}
	if !p.inSet(net.ParseIP("1.2.3.5")) {
		t.Error("resolved answer should be in the set")
	}
}

func TestObserveDNSNoDomainsIsNoopWithoutParsing(t *testing.T) {
	p := newBypassPolicy("", []string{"1.2.3.4"}) // IP/CIDR only, no domains
	// Garbage input: if observeDNS tried to parse this, dnsQuestionName/
	// dnsAnswerIPs would just fail closed anyway, but hasDomains() should
	// short-circuit before either is even called.
	p.observeDNS([]byte("not dns"), []byte("not dns either"))
}

func TestDNSQuestionName(t *testing.T) {
	query := buildDNSQuery(t, "www.Example.com.")
	if got, want := dnsQuestionName(query), "www.Example.com"; got != want {
		t.Errorf("dnsQuestionName = %q, want %q", got, want)
	}
}

func TestDNSQuestionNameGarbageInput(t *testing.T) {
	if got := dnsQuestionName([]byte("not a dns message")); got != "" {
		t.Errorf("dnsQuestionName(garbage) = %q, want empty", got)
	}
}

func TestDNSAnswerIPs(t *testing.T) {
	resp := buildDNSAnswer(t, "example.com.", [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8})
	got := dnsAnswerIPs(resp)
	if len(got) != 2 || !got[0].Equal(net.IPv4(1, 2, 3, 4)) || !got[1].Equal(net.IPv4(5, 6, 7, 8)) {
		t.Fatalf("dnsAnswerIPs = %v, want [1.2.3.4 5.6.7.8]", got)
	}
}

func TestDNSAnswerIPsGarbageInput(t *testing.T) {
	if got := dnsAnswerIPs([]byte("not a dns message")); got != nil {
		t.Errorf("dnsAnswerIPs(garbage) = %v, want nil", got)
	}
}

// --- test helpers ---

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func buildDNSQuery(t *testing.T, name string) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName(%q): %v", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("Question: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return msg
}

func buildDNSAnswer(t *testing.T, name string, ips ...[4]byte) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName(%q): %v", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("StartQuestions: %v", err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("Question: %v", err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatalf("StartAnswers: %v", err)
	}
	for _, ip := range ips {
		if err := b.AResource(
			dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: ip},
		); err != nil {
			t.Fatalf("AResource: %v", err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return msg
}
