package core

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// fakePoolCoordinator binds a loopback UDP socket standing in for one pool
// member. When respond is true it answers a "list" request with the given countries
// (a matching coordinator accepts the version hello silently, so it just ignores
// everything else); when false it blackholes every datagram — exactly what a
// client sees when a censor drops a coordinator's return traffic. It returns the
// host:port to configure.
//
// This is a ROTATION fixture, not a protocol fixture. It exists to make one member
// silent and another answer, so the tests below can assert what the client does when a
// pool member is blocked; it is deliberately the thinnest thing that produces a
// well-formed reply. The protocol itself is pinned against the REAL coordinator in
// cmd/coordinator/protocol_integration_test.go — because this fake answering a shape
// no coordinator sends is precisely how #146 shipped with a green suite.
func fakePoolCoordinator(t *testing.T, respond bool, countries []wireCountry) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	if !respond {
		// Blackhole: nothing reads the socket, so every datagram — the ICE check,
		// the ClientHello, everything — is dropped, which is what a client sees when
		// a censor drops a coordinator's return traffic. Under ADR-0062 the shaped
		// handshake is what dies here rather than the request, and the client's
		// conclusion is the same one: this member is unreachable, rotate.
		return pc.LocalAddr().String()
	}
	peer := servePeer(t, pc)
	go func() {
		for {
			raw, src, err := peer.ReadFrom()
			if err != nil {
				return
			}
			var m wire
			if json.Unmarshal(raw, &m) != nil || m.Type != "list" {
				continue
			}
			b, _ := json.Marshal(wire{Type: "countries", Countries: countries})
			_, _ = peer.WriteTo(b, src)
		}
	}()
	return pc.LocalAddr().String()
}

// TestClientRotation_DiscoversViaHealthyMember is issue #6's acceptance: with
// two coordinators configured and one blocked, the client must still discover
// the country list through the other. The client shuffles its pool, so the blocked member
// may be tried first — the budget covers that case, and either way discovery
// must succeed.
func TestClientRotation_DiscoversViaHealthyMember(t *testing.T) {
	blocked := fakePoolCoordinator(t, false, nil)
	working := fakePoolCoordinator(t, true, []wireCountry{{Country: "XX", Exits: 1, Available: 1}})

	eng, err := New(Config{
		Coordinators: []string{blocked, working},
		Roles:        []string{"client"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	got, err := eng.ListCountries(ctx, 6*time.Second)
	if err != nil {
		t.Fatalf("with one member blocked the client should still discover countries: %v", err)
	}
	if len(got) != 1 || got[0].Country != "XX" {
		t.Fatalf("unexpected countries: %+v", got)
	}
}

// TestClientRotation_AllMembersBlocked: when every pool member blackholes, the
// client exhausts the rotation, errors, and remembers both as unhealthy.
func TestClientRotation_AllMembersBlocked(t *testing.T) {
	a := fakePoolCoordinator(t, false, nil)
	b := fakePoolCoordinator(t, false, nil)

	eng, err := New(Config{Coordinators: []string{a, b}, Roles: []string{"client"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	if _, err := eng.ListCountries(ctx, 3*time.Second); err == nil {
		t.Fatal("expected an error when every pool member is blocked")
	}
	if got := len(eng.unhealthySnapshot()); got != 2 {
		t.Fatalf("expected both members marked unhealthy after rotation, got %d", got)
	}
}

// TestConnectRotation_AllMembersBlocked: with every pool member blackholed, a
// client Connect exhausts the rotation (each member tried once), errors, and
// marks every member unhealthy. Short per-mode timeouts keep it quick.
func TestConnectRotation_AllMembersBlocked(t *testing.T) {
	a := fakePoolCoordinator(t, false, nil)
	b := fakePoolCoordinator(t, false, nil)

	eng, err := New(Config{
		Coordinators: []string{a, b},
		Roles:        []string{"client"},
		Geo:          "XX", // a country to ask for; a connect names one or is refused
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.directTimeout = 200 * time.Millisecond
	eng.relayTimeout = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	if err := eng.Connect(ctx); err == nil {
		t.Fatal("expected Connect to fail when every pool member is blocked")
	}
	if got := len(eng.unhealthySnapshot()); got != 2 {
		t.Fatalf("expected both members marked unhealthy after rotation, got %d", got)
	}
}

// TestSingleCoordinatorPool: a one-member pool behaves exactly as a single
// coordinator did before the pool existed (backward compatibility).
func TestSingleCoordinatorPool(t *testing.T) {
	only := fakePoolCoordinator(t, true, []wireCountry{{Country: "US", Exits: 1, Available: 1}})

	eng, err := New(Config{Coordinators: []string{only}, Roles: []string{"client"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	got, err := eng.ListCountries(ctx, 3*time.Second)
	if err != nil {
		t.Fatalf("ListCountries: %v", err)
	}
	if len(got) != 1 || got[0].Country != "US" {
		t.Fatalf("unexpected countries: %+v", got)
	}
}
