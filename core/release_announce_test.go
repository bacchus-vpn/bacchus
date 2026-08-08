package core

import "testing"

// The accessor exists so an embedder can read the announcement as a VERSION
// rather than out of a formatted event line. These pin what it reports in the
// three states that matter.
func TestNetworkReleaseReportsWhatWasAdvertised(t *testing.T) {
	e := &Engine{}
	if got := e.NetworkRelease(); got != "" {
		t.Fatalf("a fresh engine reports %q, want the empty string — nothing has been advertised yet", got)
	}

	e.observeNetworkVersion("1.2.3")
	if got := e.NetworkRelease(); got != "1.2.3" {
		t.Fatalf("NetworkRelease = %q, want 1.2.3", got)
	}

	// A garbled advert is kept verbatim rather than dropped or coerced.
	// observeNetworkVersion refuses to act on one and so must anything reading this:
	// "the coordinator said something that is not a version" and "the coordinator
	// said nothing" are different facts, and only one of them is worth a log line.
	e.observeNetworkVersion("not-a-version")
	if got := e.NetworkRelease(); got != "not-a-version" {
		t.Fatalf("NetworkRelease after a garbled advert = %q, want it verbatim", got)
	}

	// An empty advert changes nothing, matching observeNetworkVersion's own rule
	// that the check only ever adds safety and never invents a reason to act.
	e.observeNetworkVersion("")
	if got := e.NetworkRelease(); got != "not-a-version" {
		t.Fatalf("an empty advert overwrote the last one: %q", got)
	}
}
