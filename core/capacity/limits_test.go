package capacity

import "testing"

// ParseRate/ParseBytes exist to be typed by a human reading their ISP contract, so
// the cases below are the strings such a human actually writes.
func TestParseRate(t *testing.T) {
	cases := []struct {
		in   string
		want Rate
	}{
		{"", 0}, // unset = unlimited
		{"0", 0},
		{"20Mbit", 20 * Mbit},
		{"20mbit", 20 * Mbit},
		{"20 Mbit", 20 * Mbit}, // spaces are how people actually type it
		{"1.5Gbit", 1500 * Mbit},
		{"100kbit", 100 * Kbit},
		{"100Mbps", 100 * Mbit}, // the other unit people write
		{"50M", 50 * Mbit},
		{"20000000", 20 * Mbit}, // bare bits/s
		{"2Gbit", 2 * Gbit},
	}
	for _, c := range cases {
		got, err := ParseRate(c.in)
		if err != nil {
			t.Errorf("ParseRate(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseRate(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseRateRejects(t *testing.T) {
	for _, in := range []string{"Mbit", "twenty", "20Gigglebits", "-5Mbit", "20.5.5Mbit"} {
		if got, err := ParseRate(in); err == nil {
			t.Errorf("ParseRate(%q) = %d, want an error", in, got)
		}
	}
}

func TestParseBytes(t *testing.T) {
	cases := []struct {
		in   string
		want Bytes
	}{
		{"", 0},
		{"400GB", 400 * GB},
		{"400gb", 400 * GB},
		{"1.5TB", 1500 * GB},
		{"250MB", 250 * MB},
		{"500g", 500 * GB},
		{"1000000000", GB}, // bare bytes
	}
	for _, c := range cases {
		got, err := ParseBytes(c.in)
		if err != nil {
			t.Errorf("ParseBytes(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseBytes(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestUnitsAreDecimalNotBinary pins the choice in limits.go: ISPs bill in decimal,
// so "500GB" is 500e9 and not 500*2^30. Reading it as binary would silently let a
// node overshoot its real cap by 7.4% — which is the exact overage bill issue #143
// exists to prevent, arriving quietly.
func TestUnitsAreDecimalNotBinary(t *testing.T) {
	got, err := ParseBytes("500GB")
	if err != nil {
		t.Fatal(err)
	}
	if got != 500_000_000_000 {
		t.Errorf("ParseBytes(500GB) = %d, want 500e9 (decimal, as an ISP bills it)", got)
	}
	if got == 500*1024*1024*1024 {
		t.Error("ParseBytes(500GB) parsed as binary GiB — a node would overshoot its cap by 7.4%")
	}
}

func TestRateAndBytesRoundTrip(t *testing.T) {
	for _, s := range []string{"20Mbit", "1.5Gbit", "100kbit", "2Gbit"} {
		r, err := ParseRate(s)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseRate(r.String())
		if err != nil {
			t.Fatalf("ParseRate(%q.String() = %q): %v", s, r.String(), err)
		}
		if back != r {
			t.Errorf("%q -> %d -> %q -> %d: round trip lost the value", s, r, r.String(), back)
		}
	}
	for _, s := range []string{"400GB", "1.5TB", "250MB"} {
		b, err := ParseBytes(s)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseBytes(b.String())
		if err != nil {
			t.Fatalf("ParseBytes(%q.String() = %q): %v", s, b.String(), err)
		}
		if back != b {
			t.Errorf("%q -> %d -> %q -> %d: round trip lost the value", s, b, b.String(), back)
		}
	}
}

func TestZeroRendersAsUnlimited(t *testing.T) {
	if got := Rate(0).String(); got != "unlimited" {
		t.Errorf("Rate(0).String() = %q, want %q", got, "unlimited")
	}
	if got := Bytes(0).String(); got != "unlimited" {
		t.Errorf("Bytes(0).String() = %q, want %q", got, "unlimited")
	}
}

func TestLimitsValidate(t *testing.T) {
	cases := []struct {
		name    string
		l       Limits
		wantErr bool
	}{
		{"zero value is a node with no declared limits", Limits{}, false},
		{"speed cap only", Limits{SpeedCap: 20 * Mbit}, false},
		{"quota with a billing anchor", Limits{MonthlyQuota: 400 * GB, CycleDay: 17}, false},
		{"cycle day 28 (exists in February)", Limits{MonthlyQuota: 400 * GB, CycleDay: 28}, false},
		{"cycle day 29 would skip February", Limits{MonthlyQuota: 400 * GB, CycleDay: 29}, true},
		{"cycle day 31", Limits{MonthlyQuota: 400 * GB, CycleDay: 31}, true},
		{"negative cycle day", Limits{MonthlyQuota: 400 * GB, CycleDay: -1}, true},
		{"cycle day without a quota is meaningless", Limits{CycleDay: 17}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.l.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

// The zero Limits must describe today's node exactly: uncapped and unmetered. This
// is what keeps issue #143 opt-in and the existing datacenter fleet unaffected.
func TestZeroLimitsIsTodaysNode(t *testing.T) {
	var l Limits
	if l.SpeedCap != 0 || l.MonthlyQuota != 0 {
		t.Fatal("the zero Limits must be uncapped and unmetered")
	}
	if NewLimiter(l.SpeedCap) != nil {
		t.Error("the zero Limits must produce the inert nil *Limiter")
	}
	q, err := NewQuota(l, "", epoch)
	if err != nil {
		t.Fatal(err)
	}
	if q != nil {
		t.Error("the zero Limits must produce the inert nil *Quota")
	}
	if q.Exhausted(epoch) {
		t.Error("a node with no declared quota can never be exhausted")
	}
}
