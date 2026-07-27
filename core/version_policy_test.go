package core

import (
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/version"
)

// newClientEngine builds a minimal client engine with no network I/O, for
// exercising the client version-policy latch (observeNetworkVersion /
// updateRequired) directly (issue #36, ADR-0015).
func newClientEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{"client"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return eng
}

// A network whose MAJOR is ahead of this build latches a force-major update
// requirement that updateRequired then surfaces with the required version named.
func TestObserveForcesMajorUpdate(t *testing.T) {
	eng := newClientEngine(t)
	self := version.Current()
	ahead := version.Version{Major: self.Major + 1} // one major ahead of this build

	if err := eng.updateRequired(); err != nil {
		t.Fatalf("a fresh engine must not require an update: %v", err)
	}
	eng.observeNetworkVersion(ahead.String())
	err := eng.updateRequired()
	if err == nil {
		t.Fatal("a network a major ahead must latch a force-major update requirement")
	}
	if !strings.Contains(err.Error(), ahead.String()) {
		t.Fatalf("the error should name the required version %s, got %q", ahead, err)
	}
}

// A network ahead only on MINOR/PATCH is tolerated — the client keeps working
// (skip-minor), so updateRequired stays nil.
func TestObserveToleratesMinorSkew(t *testing.T) {
	eng := newClientEngine(t)
	self := version.Current()
	minorAhead := version.Version{Major: self.Major, Minor: self.Minor + 1}

	eng.observeNetworkVersion(minorAhead.String())
	if err := eng.updateRequired(); err != nil {
		t.Fatalf("a minor-ahead network must be tolerated, got %v", err)
	}
}

// A garbled or empty advert never trips the latch — the check only adds safety,
// it never invents a reason to stop the client.
func TestObserveIgnoresGarbledAdvert(t *testing.T) {
	eng := newClientEngine(t)
	for _, bad := range []string{"", "not-a-version", "9"} {
		eng.observeNetworkVersion(bad)
		if err := eng.updateRequired(); err != nil {
			t.Fatalf("advert %q must not require an update, got %v", bad, err)
		}
	}
}
