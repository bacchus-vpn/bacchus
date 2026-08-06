package appstate

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestMain refuses to run this package's tests while something else already
// holds the client's pinned SOCKS port.
//
// SocksAddr is 127.0.0.1:1080 and it is FIXED for reasons controller.go gives at
// length, so every test here that brings up an engine binds the same port as
// every other process on this machine running the same tests. Two of them — two
// worktrees, or a `go test ./...` running beside a focused re-run — contend for
// it, and the contention does not look like contention:
//
//   - the loser's Connect fails with "bind: address already in use", so the
//     connect never reaches the branch under test and the failure is reported as
//     whatever that test was actually asserting;
//   - a test that asks the network whether anything is still listening on
//     SocksAddr sees the WINNER's listener and reports it as a leak of its own.
//
// The second of those is what bacchus#197 was filed from: a real leak was found
// by reading the code, and the flake attributed to it — one run in thirty, on a
// loaded machine, load-sensitive — is this. The leak is fixed and has a
// deterministic test in core/ now (core/listener_shutdown_test.go); this is here
// so the environmental half announces itself instead of being triaged again.
//
// It cannot catch a collision that STARTS mid-run, which is the harder case. It
// catches the common one — starting a second run while the first is going — and
// it names what to do about it.
func TestMain(m *testing.M) {
	if c, err := net.DialTimeout("tcp", SocksAddr, 500*time.Millisecond); err == nil {
		_ = c.Close()
		fmt.Fprintf(os.Stderr,
			"appstate tests: %s is already accepting connections before any test has run.\n"+
				"These tests bind the client's pinned SOCKS port, so they cannot share a machine with\n"+
				"another run of them (a second worktree, or `go test ./...` beside a focused re-run) or\n"+
				"with a real Bacchus client. Failures from here would be reported as leaks and as\n"+
				"connects that never reached the branch under test. Stop the other one and re-run.\n",
			SocksAddr)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
