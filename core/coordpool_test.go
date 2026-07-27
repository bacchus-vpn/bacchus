package core

import (
	"testing"
	"time"
)

func TestRankCoordinators(t *testing.T) {
	now := time.Unix(1000, 0)
	const cd = 30 * time.Second
	abc := []string{"a", "b", "c"}

	t.Run("all healthy preserves order", func(t *testing.T) {
		got := rankCoordinators(abc, map[string]time.Time{}, now, cd)
		if !eqStrings(got, abc) {
			t.Fatalf("got %v, want %v", got, abc)
		}
	})
	t.Run("unhealthy within cooldown sinks to the end", func(t *testing.T) {
		unhealthy := map[string]time.Time{"b": now.Add(-5 * time.Second)}
		got := rankCoordinators(abc, unhealthy, now, cd)
		want := []string{"a", "c", "b"}
		if !eqStrings(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
	t.Run("cooldown expiry restores health", func(t *testing.T) {
		unhealthy := map[string]time.Time{"b": now.Add(-60 * time.Second)}
		got := rankCoordinators(abc, unhealthy, now, cd)
		if !eqStrings(got, abc) {
			t.Fatalf("got %v, want %v", got, abc)
		}
	})
	t.Run("all cooling still returns every member", func(t *testing.T) {
		unhealthy := map[string]time.Time{
			"a": now.Add(-time.Second),
			"b": now.Add(-time.Second),
			"c": now.Add(-time.Second),
		}
		got := rankCoordinators(abc, unhealthy, now, cd)
		if len(got) != 3 {
			t.Fatalf("expected all 3 present even when all cooling, got %v", got)
		}
	})
}

func TestDedupNonEmpty(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"a:1"}, []string{"a:1"}},
		{[]string{"a:1", "b:2"}, []string{"a:1", "b:2"}},
		{[]string{" a:1 ", "b:2 "}, []string{"a:1", "b:2"}},
		{[]string{"a:1", "", "b:2"}, []string{"a:1", "b:2"}},
		{[]string{"a:1", "a:1"}, []string{"a:1"}}, // dedup
		{[]string{"", "  "}, nil},
		{nil, nil},
	}
	for _, c := range cases {
		if got := dedupNonEmpty(c.in); !eqStrings(got, c.want) {
			t.Errorf("dedupNonEmpty(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPerLinkBudget(t *testing.T) {
	if got := perLinkBudget(6*time.Second, 1); got != 6*time.Second {
		t.Fatalf("n=1: got %v, want the whole 6s", got)
	}
	if got := perLinkBudget(6*time.Second, 3); got != 2*time.Second {
		t.Fatalf("n=3: got %v, want an even 2s slice", got)
	}
	if got := perLinkBudget(1*time.Second, 10); got != 800*time.Millisecond {
		t.Fatalf("n=10: got %v, want the 800ms floor", got)
	}
	if got := perLinkBudget(5*time.Second, 0); got != 5*time.Second {
		t.Fatalf("n=0 must not divide by zero: got %v, want 5s", got)
	}
}

func TestMergeOutcome(t *testing.T) {
	// The more informative outcome wins, regardless of argument order.
	if got := mergeOutcome(coordinatorSilent, transportFailed); got != transportFailed {
		t.Fatalf("got %v, want transportFailed", got)
	}
	if got := mergeOutcome(transportFailed, coordinatorSilent); got != transportFailed {
		t.Fatalf("got %v, want transportFailed", got)
	}
	if got := mergeOutcome(coordinatorSilent, coordinatorRefused); got != coordinatorRefused {
		t.Fatalf("got %v, want coordinatorRefused", got)
	}
}

func TestHealthMemory(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"client"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(eng.unhealthySnapshot()) != 0 {
		t.Fatal("a fresh engine should have no unhealthy members")
	}
	eng.markUnhealthy("x:1")
	if _, ok := eng.unhealthySnapshot()["x:1"]; !ok {
		t.Fatal("expected x:1 to be recorded as unhealthy")
	}
	// The snapshot must be a copy: mutating it cannot affect engine state.
	snap := eng.unhealthySnapshot()
	delete(snap, "x:1")
	if _, ok := eng.unhealthySnapshot()["x:1"]; !ok {
		t.Fatal("snapshot should be a copy, not a live view")
	}
}

func eqStrings(a, b []string) bool {
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
