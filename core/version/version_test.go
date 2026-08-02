package version

import (
	"bytes"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestParseValid(t *testing.T) {
	cases := map[string]Version{
		"0.0.0":       {0, 0, 0},
		"0.1.0":       {0, 1, 0},
		"1.2.3":       {1, 2, 3},
		"10.20.30":    {10, 20, 30},
		"2.0.0":       {2, 0, 0},
		"0.0.147":     {0, 0, 147},
		"100.100.100": {100, 100, 100},
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Parse(%q) = %+v, want %+v", in, got, want)
		}
		if got.String() != in {
			t.Errorf("Parse(%q).String() = %q, want round-trip %q", in, got.String(), in)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	bad := []string{
		"",          // empty
		"1",         // too few components
		"1.2",       // too few components
		"1.2.3.4",   // too many components
		"1.2.x",     // non-numeric
		"v1.2.3",    // no leading v allowed
		"1.-2.3",    // negative
		"1..3",      // empty component
		"1.2.3-rc1", // pre-release metadata not modeled
		" 1.2.3",    // stray whitespace
	}
	for _, in := range bad {
		if got, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %+v, want error", in, got)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b Version
		want int
	}{
		{Version{1, 2, 3}, Version{1, 2, 3}, 0},
		{Version{1, 0, 0}, Version{2, 0, 0}, -1}, // major dominates
		{Version{2, 0, 0}, Version{1, 9, 9}, 1},  // major dominates minor+patch
		{Version{1, 2, 0}, Version{1, 3, 0}, -1}, // minor dominates patch
		{Version{1, 2, 5}, Version{1, 2, 4}, 1},  // patch
		{Version{0, 1, 0}, Version{0, 1, 0}, 0},
		{Version{0, 0, 1}, Version{0, 0, 0}, 1},
	}
	for _, c := range cases {
		if got := c.a.Compare(c.b); got != c.want {
			t.Errorf("%v.Compare(%v) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Compare must be antisymmetric.
		if got := c.b.Compare(c.a); got != -c.want {
			t.Errorf("%v.Compare(%v) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestCurrentIsParseable(t *testing.T) {
	// Current() must never panic, stamped or not. Stamped, it must round-trip
	// exactly what it was stamped with; unstamped, it is the zero release.
	got := Current()
	switch {
	case Stamped() && got.String() != current:
		t.Fatalf("Current().String() = %q, want %q (the stamped `current`)", got.String(), current)
	case !Stamped() && got != (Version{}):
		t.Fatalf("Current() = %v on an unstamped build, want the zero version", got)
	}
}

// requireStampEnv turns TestStampMatchesTheVersionFile's skip into a failure.
// Same shape, and the same reason, as BACCHUS_NETD_REQUIRE_NS in CI: a check
// that silently skips when its precondition is missing reports green over
// nothing, and the precondition here is the very thing under test.
const requireStampEnv = "BACCHUS_REQUIRE_STAMP"

// TestStampMatchesTheVersionFile is the check that the -ldflags -X every build
// path passes actually LANDS, and it is the reason CI runs this package twice.
//
// The failure it exists for is quiet in a way nothing else here would catch: a
// -X whose symbol path does not resolve — a renamed var, a moved package, a
// typo'd module path — is IGNORED BY THE LINKER WITHOUT ERROR. The build
// succeeds, the installer reports success, and the binary reports 0.0.0 forever.
// So the assertion cannot be "the flag was passed"; it has to be "the value
// arrived", read back out of the linked binary and compared against the file it
// came from (issue #128).
func TestStampMatchesTheVersionFile(t *testing.T) {
	want := versionFile(t)
	if !Stamped() {
		if os.Getenv(requireStampEnv) != "" {
			t.Fatalf("%s is set but this test binary is unstamped: the -X did not reach %s.current — "+
				"check the symbol path in the -ldflags that built it, because the linker does not report a bad one",
				requireStampEnv, "github.com/bacchus-vpn/bacchus/core/version")
		}
		t.Skipf("this test binary is unstamped (a bare `go test`), so there is no stamp to check; "+
			"CI runs this package again with the stamp and %s set", requireStampEnv)
	}
	if got := Current().String(); got != want {
		t.Fatalf("Current() = %s but VERSION says %s — a stamped build must carry the file's number", got, want)
	}
}

// TestVersionFileIsCanonical guards the source of truth itself. Every shipped
// binary is stamped with this file's contents, and Current() PANICS on a
// malformed stamp — so a stray "v", a pre-release suffix or an editor's second
// line in VERSION is not a build-time error, it is every binary of that release
// dying at startup. This is the cheapest place to catch it.
func TestVersionFileIsCanonical(t *testing.T) {
	raw, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("reading the VERSION file: %v", err)
	}
	s := string(raw)
	if !strings.HasSuffix(s, "\n") || strings.Count(s, "\n") != 1 {
		t.Errorf("VERSION must be exactly one line ending in a newline, got %q", s)
	}
	trimmed := strings.TrimSuffix(s, "\n")
	if trimmed != strings.TrimSpace(trimmed) {
		t.Fatalf("VERSION has surrounding whitespace: %q — it is pasted into a -ldflags -X verbatim", trimmed)
	}
	v, err := Parse(trimmed)
	if err != nil {
		t.Fatalf("VERSION (%q) is not a bare MAJOR.MINOR.PATCH: %v", trimmed, err)
	}
	if v.String() != trimmed {
		t.Fatalf("VERSION (%q) does not round-trip: parsed back as %s", trimmed, v)
	}
}

// versionFile returns the release number the repository declares, for tests that
// compare a build against it.
func versionFile(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("reading the VERSION file: %v", err)
	}
	return strings.TrimSpace(string(raw))
}

// A build stamped with something that is not a release fails at startup, and
// does NOT degrade the way an unstamped build does. The asymmetry is the point
// of this test: unstamped is what an ordinary `go build` produces and it has a
// representable answer (0.0.0, no release), while a malformed stamp has none,
// and the only alternative to failing is inventing a release for a fence that
// must never be handed one.
//
// A release candidate leads the table because it is the case that will actually
// be attempted: `v1.0.0-rc1` is an ordinary tag to want, and under the
// v<VERSION> convention it would put 1.0.0-rc1 in VERSION and stamp it. Three
// validators reject it before a build can carry it (install.sh's version_valid,
// TestVersionFileIsCanonical, and CI's shape checks on VERSION and the tag) —
// this pins what happens if all three are bypassed.
func TestMalformedStampFailsAtStartup(t *testing.T) {
	for _, bad := range []string{"1.0.0-rc1", "1.0.0+build.7", "v1.0.0", "1.0", "0.1.0\n"} {
		t.Run(bad, func(t *testing.T) {
			restore := current
			defer func() {
				current = restore
				r := recover()
				if r == nil {
					t.Fatalf("a build stamped %q must not start; Current() returned instead", bad)
				}
				msg, ok := r.(string)
				if !ok {
					t.Fatalf("panicked with %T, want the string message a release engineer can act on", r)
				}
				// Quoted, which is how the message carries it: a stamp with a
				// stray newline in it has to be readable in a panic, and the
				// raw bytes would put a line break through the middle of one.
				for _, want := range []string{strconv.Quote(bad), "MAJOR.MINOR.PATCH", "VERSION"} {
					if !strings.Contains(msg, want) {
						t.Errorf("the panic must name %s, got:\n%s", want, msg)
					}
				}
			}()
			current = bad
			_ = Current()
		})
	}
}

// The panic text names the pre-release case in the words someone tagging would
// use, because that is the mistake this message exists to answer.
func TestMalformedStampMessageNamesPreRelease(t *testing.T) {
	_, err := Parse("1.0.0-rc1")
	if err == nil {
		t.Fatal("Parse accepted a pre-release version")
	}
	msg := malformedStampMessage("1.0.0-rc1", err)
	for _, want := range []string{"pre-release", "1.0.0-rc1", "leading v"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the panic message must mention %q, got:\n%s", want, msg)
		}
	}
}

// An unstamped build says so — once, loudly — and keeps running. Both halves
// matter: the warning is the only thing that distinguishes it from a release
// build (ADR-0015's fence compares numbers, and this one has none), and the
// running is why it is a warning at all rather than a refusal.
func TestUnstampedWarnsOnceAndKeepsRunning(t *testing.T) {
	if Stamped() {
		t.Skip("this test binary was stamped, so there is no unstamped path to exercise here")
	}
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	// Any earlier test in this binary may already have spent the once.
	warnUnstamped = sync.Once{}

	if got := Current(); got != (Version{}) {
		t.Fatalf("Current() = %v on an unstamped build, want 0.0.0", got)
	}
	first := buf.String()
	if !strings.Contains(first, "WARNING") || !strings.Contains(first, "not stamped") {
		t.Fatalf("an unstamped build must warn loudly, got %q", first)
	}
	if !strings.Contains(first, "VERSION") {
		t.Errorf("the warning must name VERSION, the file that fixes it: %q", first)
	}

	if got := Current(); got != (Version{}) {
		t.Fatalf("second Current() = %v, want 0.0.0", got)
	}
	if buf.String() != first {
		t.Fatalf("the warning repeated; a node re-states its release on every register, so it must fire once:\n%s", buf.String())
	}
}

// --- Policy predicates (TODO(#36)): the tables below are the spec the two
// predicates must satisfy. They stay RED until ServingAllowed / ClientMustUpdate
// are implemented. ---

func TestServingAllowed(t *testing.T) {
	floor := Version{0, 2, 0}
	cases := []struct {
		name string
		node Version
		want bool
	}{
		{"exactly at floor serves", Version{0, 2, 0}, true},
		{"one patch below floor is fenced", Version{0, 1, 9}, false},
		{"one minor below floor is fenced", Version{0, 1, 0}, false},
		{"major below floor is fenced", Version{0, 1, 99}, false},
		{"one patch above floor serves", Version{0, 2, 1}, true},
		{"minor above floor serves", Version{0, 3, 0}, true},
		{"major above floor serves", Version{1, 0, 0}, true},
	}
	for _, c := range cases {
		if got := ServingAllowed(c.node, floor); got != c.want {
			t.Errorf("%s: ServingAllowed(%v, floor=%v) = %v, want %v", c.name, c.node, floor, got, c.want)
		}
	}
}

// A floor of 0.0.0 is the "disabled" sentinel the coordinator uses when the
// operator sets no minimum: nothing is ever below it, so nobody is fenced.
func TestServingAllowedDisabledFloor(t *testing.T) {
	floor := Version{0, 0, 0}
	for _, node := range []Version{{0, 0, 0}, {0, 1, 0}, {5, 4, 3}} {
		if !ServingAllowed(node, floor) {
			t.Errorf("ServingAllowed(%v, floor=0.0.0) = false, want true (disabled floor fences nobody)", node)
		}
	}
}

func TestClientMustUpdate(t *testing.T) {
	network := Version{2, 4, 1}
	cases := []struct {
		name   string
		client Version
		want   bool
	}{
		{"same version keeps working", Version{2, 4, 1}, false},
		{"behind on patch is tolerated", Version{2, 4, 0}, false},
		{"behind on minor is tolerated", Version{2, 0, 0}, false},
		{"way behind on minor still tolerated", Version{2, 1, 9}, false},
		{"one major behind must update", Version{1, 9, 9}, true},
		{"two majors behind must update", Version{0, 9, 9}, true},
		{"newer major is not forced to downgrade", Version{3, 0, 0}, false},
		{"newer minor is fine", Version{2, 5, 0}, false},
	}
	for _, c := range cases {
		if got := ClientMustUpdate(c.client, network); got != c.want {
			t.Errorf("%s: ClientMustUpdate(client=%v, network=%v) = %v, want %v", c.name, c.client, network, got, c.want)
		}
	}
}
