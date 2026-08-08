package main

import (
	"net"
	"strings"
	"testing"
)

// A node's build revision on the register wire (issue #182, ADR-0063): the
// coordinator's own startup line has named ITS revision since #114 (coordBuild),
// but a node's was never on the wire at all, so pairing the two still meant
// reading the node's binary by hand. This is the coordinator's receiving half —
// see core/engine.go's nodeBuildRevision for the sending half.
//
// MUTATION: drop `build` from either "registered" line's format/args (revert to
// the pre-#182 line) — that role's subtest goes red.
func TestRegisterLogsNodeBuild(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	peer := fakePeer(t)

	t.Run("exit", func(t *testing.T) {
		resetRegistry(t)
		sink := captureLog(t)
		handle(wire{Type: "register", Role: "exit", ID: "e1", Country: "rs", Addr: docAddr, Release: "0.4.1", Build: "a868e6e3c447"},
			peer.LocalAddr().(*net.UDPAddr))
		if got := sink.String(); !strings.Contains(got, "exit registered:") || !strings.Contains(got, "build=a868e6e3c447") {
			t.Fatalf("the exit registration line must carry the node's build, got:\n%s", got)
		}
	})

	t.Run("relay", func(t *testing.T) {
		resetRegistry(t)
		sink := captureLog(t)
		handle(wire{Type: "register", Role: "relay", ID: "r1", Country: "rs", Release: "0.4.1", Build: "a868e6e3c447"},
			peer.LocalAddr().(*net.UDPAddr))
		if got := sink.String(); !strings.Contains(got, "relay registered:") || !strings.Contains(got, "build=a868e6e3c447") {
			t.Fatalf("the relay registration line must carry the node's build, got:\n%s", got)
		}
	})
}

// A node built in a git WORKTREE or under `go test` sends no revision at all —
// the toolchain records VCS data only from a checkout with a real .git
// directory, which is how every lane in this project builds (core/engine.go's
// nodeBuildRevision doc). That absence is the ORDINARY case and must read as
// such, exactly like releaseOrUnknown already does for an empty release: named,
// never printed as a blank, and never treated as suspicious on its own — it is
// a MISMATCH against this coordinator's own revision that would be evidence,
// and this line does not even attempt that comparison.
//
// MUTATION: print m.Build unchanged instead of falling back to "unknown" — goes
// red on the "build=unknown" assertion (the line renders "build= " instead).
func TestRegisterLogsUnknownBuildForAWorktreeNode(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "exit", ID: "worktree-node", Country: "rs", Addr: docAddr, Release: "0.4.1"},
		peer.LocalAddr().(*net.UDPAddr))

	if got := sink.String(); !strings.Contains(got, "build=unknown") {
		t.Fatalf("a node reporting no build revision must log build=unknown, got:\n%s", got)
	}
}
