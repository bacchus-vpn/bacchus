package main

import "testing"

func TestParseCoordinators(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"host1:8080", []string{"host1:8080"}},
		{"host1:8080,host2:8080", []string{"host1:8080", "host2:8080"}},
		{" host1:8080 , host2:8080 ", []string{"host1:8080", "host2:8080"}},
		{"host1:8080,,host2:8080", []string{"host1:8080", "host2:8080"}},
		{"host1:8080,host1:8080", []string{"host1:8080"}}, // dedup
		{"", nil},
		{" , ", nil},
	}
	for _, c := range cases {
		got := parseCoordinators(c.in)
		if !equalStrings(got, c.want) {
			t.Errorf("parseCoordinators(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

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
