package version

import "testing"

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
	// Current() must never panic for the value shipped in source; if someone
	// edits `current` to a malformed string this catches it in CI.
	got := Current()
	if got.String() != current {
		t.Fatalf("Current().String() = %q, want %q (the `current` source var)", got.String(), current)
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
