package core

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// Client half of the per-connect idempotency key (issue #1, ADR-0042 §2).
//
// The coordinator collapses the copies of one connect by their nonce, which only works
// if this client puts the SAME nonce on all of them. Minting it one line lower — inside
// the send loop rather than once per request — would leave every copy carrying a
// distinct key and restore the pre-#1 several-exits-per-request behaviour exactly, with
// nothing on either side failing and no error anywhere. That is what this pins.

// collectConnects drives one pairing request through a link pointed at a socket nobody
// answers, and returns the connect datagrams that reached it. The request times out (by
// design — the point is what went OUT), so the timeout is kept short.
func collectConnects(t *testing.T, e *Engine, l *coordLink, coord *net.UDPConn, req connectReq) []wire {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.attemptWith(context.Background(), l, req, nil, 200*time.Millisecond, nil)
	}()

	var out []wire
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = coord.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		buf := make([]byte, 65535)
		n, _, err := coord.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var m wire
		if json.Unmarshal(buf[:n], &m) != nil {
			continue
		}
		if m.Type == "connect" {
			out = append(out, m)
		}
	}
	<-done
	return out
}

func nonceTestEngine(t *testing.T, addr string) (*Engine, *coordLink) {
	t.Helper()
	e, err := New(Config{
		Coordinators: []string{addr},
		Roles:        []string{RoleClient},
		SocksAddr:    "127.0.0.1:0",
		Geo:          "NL",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(e.Stop)
	links, err := dialPool([]string{addr}, func(string, error) {})
	if err != nil {
		t.Fatalf("dialPool: %v", err)
	}
	return e, links[0]
}

// TestOneConnectCarriesOneNonceAcrossItsRetransmits: the three copies sendN puts on the
// wire are one request, and must say so.
func TestOneConnectCarriesOneNonceAcrossItsRetransmits(t *testing.T) {
	coord := fakeCoordinator(t)
	e, l := nonceTestEngine(t, coord.LocalAddr().String())

	sent := collectConnects(t, e, l, coord, connectReq{country: "NL", mode: modeDirect})

	if len(sent) < 2 {
		t.Fatalf("saw %d connect datagram(s); this test needs the retransmits to observe (sendN sends 3)", len(sent))
	}
	if sent[0].Nonce == "" {
		t.Fatal("the connect carried no nonce — a coordinator refuses an unnonced connect (connect-needs-nonce), so this client could not pair at all")
	}
	for i, m := range sent {
		if m.Nonce != sent[0].Nonce {
			t.Fatalf("copy %d carried nonce %q, copy 0 carried %q — the copies of ONE connect must share one key, or the coordinator assigns each of them a separate exit (ADR-0042 §2)",
				i, m.Nonce, sent[0].Nonce)
		}
	}
}

// TestSeparateConnectsCarrySeparateNonces is the non-vacuity half, and it is what stops
// the obvious wrong fix: a nonce derived once per engine, or a constant, would satisfy
// the test above perfectly and would then collapse every request this client ever makes
// onto its first assignment — no retry, no mode fallback, no reconnect.
func TestSeparateConnectsCarrySeparateNonces(t *testing.T) {
	coord := fakeCoordinator(t)
	e, l := nonceTestEngine(t, coord.LocalAddr().String())

	first := collectConnects(t, e, l, coord, connectReq{country: "NL", mode: modeDirect})
	second := collectConnects(t, e, l, coord, connectReq{country: "NL", mode: modeRelay})

	if len(first) == 0 || len(second) == 0 {
		t.Fatalf("saw %d then %d connect datagram(s); need both requests on the wire", len(first), len(second))
	}
	if first[0].Nonce == second[0].Nonce {
		t.Errorf("two separate pairing requests reused nonce %q — a fresh request must be assigned afresh; only retransmits collapse", first[0].Nonce)
	}
}
