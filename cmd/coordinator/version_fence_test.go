package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/version"
)

// setPolicy sets the version-policy globals (and disables admission) for one
// test, restoring them afterwards so fence tests don't leak state into the
// hello/registry tests that share these package globals.
func setPolicy(t *testing.T, floor, release string) {
	t.Helper()
	f, err := version.Parse(floor)
	if err != nil {
		t.Fatalf("bad test floor %q: %v", floor, err)
	}
	prevFloor, prevRelease, prevAdm := servingFloor, coordRelease, admissionVerifier
	servingFloor, coordRelease, admissionVerifier = f, release, nil
	t.Cleanup(func() { servingFloor, coordRelease, admissionVerifier = prevFloor, prevRelease, prevAdm })
}

// readReject reads one datagram the coordinator sent back to peer, asserts it is
// a reject, and returns the reason.
func readReject(t *testing.T, peer *net.UDPConn) string {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected a reject reply, got none: %v", err)
	}
	var m wire
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if m.Type != "reject" {
		t.Fatalf("expected a reject, got %q (reason %q)", m.Type, m.Reason)
	}
	return m.Reason
}

// expectSilence asserts the coordinator sent nothing back — register replies
// nothing on success, exactly like a matching hello.
func expectSilence(t *testing.T, peer *net.UDPConn) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 2048)
	if _, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Fatal("expected no reply, but the coordinator sent one")
	}
}

// A node whose release is below the floor is rejected and never enters the
// registry — it must not be matched to any client (issue #36, ADR-0015).
func TestRegisterBelowFloorIsFenced(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.2.0", "0.2.0")
	resetRegistry(t)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "exit", ID: "stale-exit", Country: "rs", Addr: "1.2.3.4:20000", Release: "0.1.0"}, peer.LocalAddr().(*net.UDPAddr))

	if reason := readReject(t, peer); !strings.Contains(reason, "below the minimum serving version") {
		t.Fatalf("reject reason should explain the fence, got %q", reason)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := exits["stale-exit"]; ok {
		t.Fatal("a fenced node must not be added to the exit registry")
	}
}

// A node exactly at the floor serves — the floor is the oldest acceptable
// release, not the first rejected one.
func TestRegisterAtFloorServes(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.2.0", "0.2.0")
	resetRegistry(t)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "exit", ID: "current-exit", Country: "rs", Addr: "1.2.3.4:20000", Release: "0.2.0"}, peer.LocalAddr().(*net.UDPAddr))

	expectSilence(t, peer)
	mu.Lock()
	defer mu.Unlock()
	if _, ok := exits["current-exit"]; !ok {
		t.Fatal("a node at the floor must be registered")
	}
}

// With a floor set, a node from before the release field existed can't prove it
// is current, so it is fenced.
func TestRegisterNoVersionFencedWhenFloorSet(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.2.0", "0.2.0")
	resetRegistry(t)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "relay", ID: "legacy-relay"}, peer.LocalAddr().(*net.UDPAddr))

	if reason := readReject(t, peer); !strings.Contains(reason, "no valid release") {
		t.Fatalf("reject reason should explain the missing version, got %q", reason)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := relays["legacy-relay"]; ok {
		t.Fatal("a no-version node must be fenced when a floor is set")
	}
}

// The fence is opt-in: with the default 0.0.0 floor, every node serves —
// including one that reports no version — so enabling versioning is backward
// compatible.
func TestRegisterFenceDisabledServesEveryone(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.1.0")
	resetRegistry(t)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "relay", ID: "legacy-relay"}, peer.LocalAddr().(*net.UDPAddr))

	expectSilence(t, peer)
	mu.Lock()
	defer mu.Unlock()
	if _, ok := relays["legacy-relay"]; !ok {
		t.Fatal("with the fence disabled, a no-version node must still register")
	}
}

// The coordinator advertises its own release on the exits reply so a client can
// apply the force-major / skip-minor rule.
func TestListReplyAdvertisesRelease(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "1.2.3")
	resetRegistry(t)
	peer := fakePeer(t)

	handle(wire{Type: "list"}, peer.LocalAddr().(*net.UDPAddr))

	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected an exits reply: %v", err)
	}
	var m wire
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Type != "countries" {
		t.Fatalf("expected exits, got %q", m.Type)
	}
	if m.Release != "1.2.3" {
		t.Fatalf("exits reply must advertise the coordinator release, got %q", m.Release)
	}
}
