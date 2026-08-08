package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/handshake"
)

// resetHelloRejectLog clears the bound's state for one test and restores it
// afterwards. It is package state that outlives a single test — every test in
// this binary shares one process — so a test that did not reset it would pass or
// fail depending on which test ran before it.
func resetHelloRejectLog(t *testing.T) {
	t.Helper()
	prevAt, prevN := helloRejectLogged, helloRejectSuppressed
	helloRejectLogged, helloRejectSuppressed = time.Time{}, 0
	t.Cleanup(func() { helloRejectLogged, helloRejectSuppressed = prevAt, prevN })
}

// The bound itself (issue #217). A flood of rejected hellos writes ONE line, not
// one per datagram, and the line that eventually follows says how many it stood
// for.
//
// MUTATION: drop the interval test in noteHelloReject and log unconditionally —
// the first assertion goes red at 200 lines instead of 1.
func TestHelloRejectLogIsBoundedToOneLinePerInterval(t *testing.T) {
	resetHelloRejectLog(t)
	setPC(t)
	peer := fakePeer(t)
	sink := captureLog(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	for i := 0; i < 200; i++ {
		noteHelloReject(time.Unix(1000, 0), "not a bacchus peer (bad magic)")
	}
	if n := countLines(sink.String(), "hello rejected"); n != 1 {
		t.Fatalf("200 rejected hellos wrote %d log lines, want 1 — one line per spoofed datagram is how a log becomes as good as no log (issue #213):\n%s", n, sink.String())
	}

	// The next interval opens, and the line that comes through accounts for what
	// was suppressed rather than pretending nothing happened.
	noteHelloReject(time.Unix(1000, 0).Add(helloRejectLogInterval), "not a bacchus peer (bad magic)")
	got := sink.String()
	if n := countLines(got, "hello rejected"); n != 2 {
		t.Fatalf("the interval did not reopen: %d lines\n%s", n, got)
	}
	if !strings.Contains(got, "199 further rejection(s)") {
		t.Fatalf("the second line does not carry what it stood for:\n%s", got)
	}

	// And the source address is never named: it is unauthenticated and spoofable,
	// so under the very flood this bound exists for it is the attacker's choice.
	if strings.Contains(got, src.IP.String()) || strings.Contains(got, "127.0.0.1") {
		t.Errorf("the rejection line names a source address:\n%s", got)
	}
}

// Bounding the log must not bound the REPLY. cmd/coordinator-probe's negative
// control IS this reject (ADR-0064 §4), and a probe run happening to land inside
// a suppressed window must still be answered — otherwise the pin's verification
// depends on how recently somebody else sent a bad hello.
//
// MUTATION: move send() inside noteHelloReject's "logged" branch — this goes red
// on the second datagram.
func TestHelloRejectRepliesEvenWhenTheLogIsSuppressed(t *testing.T) {
	resetHelloRejectLog(t)
	setPC(t)
	peer := fakePeer(t)
	captureLog(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	for i := 1; i <= 5; i++ {
		handle(wire{Type: "hello", Magic: "not-bacchus", Version: handshake.ProtocolVersion}, src)
		if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		buf := make([]byte, 1024)
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("datagram %d drew no reject (%v) — the probe's control would report this coordinator as not a signaling port at all, which ADR-0064 defines as NOT a pass", i, err)
		}
		if !strings.Contains(string(buf[:n]), "reject") {
			t.Fatalf("datagram %d drew %q, want a reject", i, buf[:n])
		}
	}
}

// The reflector, measured on the real path rather than asserted (issue #217).
//
// The card measured the payload — 16 bytes in, 59 out, 3.7x — and that is the
// right number for the wrong denominator: a reflector spends BANDWIDTH, and every
// datagram on the wire carries 28 further bytes of IPv4 + UDP header that the
// attacker pays for too. On the wire it is 87 against 44.
//
// This pins the figure so a longer reason string cannot raise it unnoticed, which
// is the only way it grows: handshake.Check's reasons are the only attacker-facing
// text on this path.
func TestHelloRejectAmplificationStaysBounded(t *testing.T) {
	resetHelloRejectLog(t)
	captureLog(t)
	addr := signalingPortUnderTest(t)

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// The smallest datagram that draws a reject: no magic at all, which
	// handshake.Check refuses before it compares any version.
	req := []byte(`{"type":"hello"}`)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no reject came back: %v", err)
	}

	// 20 bytes of IPv4 header + 8 of UDP, on each side.
	const overhead = 28
	wireIn, wireOut := len(req)+overhead, n+overhead
	factor := float64(wireOut) / float64(wireIn)
	t.Logf("hello reject: %d -> %d bytes of payload (%.1fx), %d -> %d on the wire (%.2fx)",
		len(req), n, float64(n)/float64(len(req)), wireIn, wireOut, factor)

	// answerSTUN on this same port is 48 -> 68 on the wire, 1.42x, accepted in
	// ADR-0060. This one is larger and stays in the same class; what must not
	// happen is it drifting upward silently.
	const bound = 2.0
	if factor > bound {
		t.Errorf("a spoofed source now buys %.2fx off this port (%d -> %d bytes on the wire), above the %.1fx this path is priced at.\n"+
			"The reason strings are the only thing here that can grow: see handshake.Check.", factor, wireIn, wireOut, bound)
	}
}

// The assertion wave ruling R2 exists for, made rather than assumed: the real
// cmd/coordinator-probe binary, run against the PRODUCTION packet loop of this
// build, still exits 0.
//
// The probe's control is a deliberately-mismatched hello drawing a reject. It was
// chosen because it is OLDER than the capability being probed — the coordinator's
// TURN port answers a Binding Request byte-identically on every build ever shipped
// (ADR-0060), so without a control a probe aimed one port sideways passes against
// a coordinator of any age. Anything that silences or gates that reject turns
// every future deployment pin into "control ABSENT, capability ok" — exit 4, which
// ADR-0064 defines as explicitly NOT a pass.
//
// The two halves live in two package mains and cannot import each other, so this
// builds the probe and runs it. Nothing here is a second description of either
// side: it is the shipped binary against the shipped read loop.
//
// MUTATION: make handle()'s hello case reply only to a source it has admitted —
// the probe drops to exit 4 and this goes red with the verdict in the failure.
func TestCoordinatorProbePassesAgainstThisBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds cmd/coordinator-probe")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain on PATH, so the probe cannot be built here: %v", err)
	}

	resetHelloRejectLog(t)
	captureLog(t)
	addr := signalingPortUnderTest(t)

	probe := filepath.Join(t.TempDir(), "coordinator-probe")
	if runtimeIsWindows() {
		probe += ".exe"
	}
	build := exec.Command(goBin, "build", "-o", probe, "./cmd/coordinator-probe")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building cmd/coordinator-probe: %v\n%s", err, out)
	}

	run := exec.Command(probe, "-addr", addr.String(), "-timeout", "5s")
	out, err := run.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("running the probe: %v\n%s", err, out)
		}
		code = ee.ExitCode()
	}
	if code != 0 {
		t.Fatalf("the probe exits %d against this build, want 0.\n"+
			"Exit 4 in particular means its negative control went silent, which ADR-0064 defines as NOT a pass —\n"+
			"every deployment pin from here on would fail its own verification.\n%s", code, out)
	}
	if !strings.Contains(string(out), "reject:") {
		t.Errorf("the probe passed without its control answering — read the verdict:\n%s", out)
	}
}

func runtimeIsWindows() bool { return os.PathSeparator == '\\' }
