//go:build linux

// The test harness ADR-0049's "How #37 gets tested" section calls for: a user
// namespace plus a network namespace, which give an unprivileged process a
// real, isolated kernel network stack — real netlink, real nftables, a real
// TUN device. The helper runs inside one and is asserted against actual kernel
// state rather than against a recorded command sequence.
//
// This is the capability bacchus#59 did not have. The Windows enforcement tests
// drive an injected PowerShell runner and assert the ORDER of the scripts they
// would have run; whether Windows honours those cmdlets is an OS guarantee no
// Go test on that platform can reach, which is why ADR-0039's amendment records
// that run as outstanding and #88 still holds it. Here the assertion is the
// kernel's own answer.
//
// What this does NOT prove is stated at the same volume, because the honest
// scope of a namespace is narrow: it is a synthetic network. A real desktop has
// systemd-resolved, NetworkManager, a physical adapter with its own driver
// quirks, and a distribution's own nftables rules already loaded. None of that
// is here. Passing these tests means the mechanism is right, not that the
// machine is covered — the same distinction #59 drew, and the same one #88 is
// still open on for Windows.
package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// nsEnvVar marks a test process that is already inside the namespace.
const nsEnvVar = "BACCHUS_NETD_TEST_NS"

// requireEnvVar turns a missing-namespace skip into a failure. CI sets it, so a
// runner that cannot create user namespaces fails loudly instead of reporting a
// green job over tests that never ran. A silent skip on the one job that
// provides this lane's only real-kernel coverage would read as "verified" while
// verifying nothing.
const requireEnvVar = "BACCHUS_NETD_REQUIRE_NS"

// inNamespace re-runs the calling test inside a fresh user+network namespace
// and reports whether the caller is the outer process (which must then return
// without running the test body).
//
// Re-exec rather than raw unshare(2): unshare(CLONE_NEWUSER) fails with EINVAL
// in a multithreaded process, and the Go runtime is multithreaded before the
// first test runs. Handing the namespace creation to a fresh single-threaded
// process is the standard way out, and `unshare -Ur` also writes the uid/gid
// maps, which is fiddly to get right by hand.
func inNamespace(t *testing.T) bool {
	t.Helper()
	if os.Getenv(nsEnvVar) == "1" {
		return false // already inside: run the body
	}

	if _, err := exec.LookPath("unshare"); err != nil {
		skipOrFail(t, "unshare(1) not found")
		return true
	}

	// -Ur: a user namespace with our uid mapped to root inside it, which is
	// what grants CAP_NET_ADMIN over the netns below without any real
	// privilege on the host.
	cmd := exec.Command("unshare", "-Ur", "--net", os.Args[0],
		"-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), nsEnvVar+"=1")
	out, err := cmd.CombinedOutput()
	text := string(out)

	// A namespace this environment refuses to create is a skip, not a failure —
	// unless CI asked for it to be a failure.
	if err != nil && (strings.Contains(text, "Operation not permitted") ||
		strings.Contains(text, "unshare failed")) && !strings.Contains(text, "--- FAIL") {
		skipOrFail(t, "cannot create a user+network namespace here:\n"+text)
		return true
	}
	if err != nil {
		t.Fatalf("in-namespace run failed: %v\n%s", err, text)
	}
	// The child's own skip must not be laundered into a pass by the parent.
	if strings.Contains(text, "--- SKIP") {
		skipOrFail(t, "skipped inside the namespace:\n"+text)
	}
	return true
}

func skipOrFail(t *testing.T, msg string) {
	t.Helper()
	if os.Getenv(requireEnvVar) == "1" {
		t.Fatalf("%s is set, so this may not be skipped: %s", requireEnvVar, msg)
	}
	t.Skip(msg)
}

// ipCmd runs an iproute2 command to build a test FIXTURE. The helper under test
// never shells out — ADR-0049 §4 forbids it, and rtnetlink.go/nft.go are the
// evidence — but a test is free to use whatever is convenient to arrange the
// world it then asserts against with netlink. Using `ip` here also keeps the
// fixture honest: it is a second, independent implementation, so a shared bug
// between setup and assertion is not possible.
func ipCmd(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func nftCmd(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// fixtureUplink builds a synthetic "physical" interface with an address and a
// default route, so defaultGateway has something to read. A dummy link is
// enough: nothing in this helper cares what carries the packets, only what the
// routing table says.
func fixtureUplink(t *testing.T) {
	t.Helper()
	ipCmd(t, "link", "add", "eth-test", "type", "dummy")
	ipCmd(t, "addr", "add", "192.0.2.2/24", "dev", "eth-test")
	ipCmd(t, "link", "set", "eth-test", "up")
	ipCmd(t, "route", "add", "default", "via", "192.0.2.1", "dev", "eth-test")
	ipCmd(t, "link", "set", "lo", "up")
}
