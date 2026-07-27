package appstate

import (
	"reflect"
	"testing"
)

func TestNormalizeBypassMode(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"include", BypassModeInclude},
		{"Include", BypassModeInclude},
		{"INCLUDE", BypassModeInclude},
		{"  include  ", BypassModeInclude},
		{"exclude", BypassModeExclude},
		{"", BypassModeExclude},         // unset config field
		{"typo", BypassModeExclude},     // anything unrecognized defaults safe
		{"includes", BypassModeExclude}, // not an exact match
	}
	for _, c := range cases {
		if got := NormalizeBypassMode(c.in); got != c.want {
			t.Errorf("NormalizeBypassMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitBypassLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "example.com", []string{"example.com"}},
		{"multiple", "example.com\n10.0.0.0/8\nvk.com", []string{"example.com", "10.0.0.0/8", "vk.com"}},
		{"blank lines dropped", "example.com\n\n\nvk.com\n", []string{"example.com", "vk.com"}},
		{"whitespace trimmed", "  example.com  \n\tvk.com\t", []string{"example.com", "vk.com"}},
		{"only whitespace", "   \n\t\n  ", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SplitBypassLines(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("SplitBypassLines(%q) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}

func TestJoinBypassLinesRoundTrips(t *testing.T) {
	cases := [][]string{
		nil,
		{"example.com"},
		{"example.com", "10.0.0.0/8", "vk.com"},
	}
	for _, c := range cases {
		joined := JoinBypassLines(c)
		got := SplitBypassLines(joined)
		if !reflect.DeepEqual(got, c) && !(len(got) == 0 && len(c) == 0) {
			t.Errorf("SplitBypassLines(JoinBypassLines(%#v)) = %#v, want %#v", c, got, c)
		}
	}
}
