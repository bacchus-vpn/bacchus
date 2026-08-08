package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// "Answered but unroutable" must not be reported as silence (issue #5).
//
// Silence is the mesh-walk trigger (#115): every coordinator unreachable, so a live one
// has to be rediscovered through a peer and the engine rebuilt against it. A coordinator
// that is up and answering in a shape this build cannot parse produces the same
// non-event at every leg that waits for a reply — nothing usable arrives, the deadline
// expires — and the recovery it wants is the opposite one. Walking the mesh there tears
// down a working engine to rebuild it against coordinators that answer identically,
// while the configured one was healthy throughout.
//
// The version fence cannot catch it either: observeNetworkVersion runs only for
// session/countries/error, so a reply this build cannot route never reaches the
// force-major check. `noteUnroutable` saw the condition and only logged it.

// unroutableCoordinator answers every datagram with a well-formed message of a type this
// build does not route — the shape an older coordinator produces (`{"type":"exits"}` was
// the real one, retired by #146) or a newer one this build has not learned yet.
//
// It answers EVERY request, so the member is unambiguously up: whatever the client
// concludes, it cannot have concluded it from silence.
func unroutableCoordinator(t *testing.T, replyType string) string {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	peer := servePeer(t, ln)
	go func() {
		for {
			raw, src, err := peer.ReadFrom()
			if err != nil {
				return
			}
			var m wire
			if json.Unmarshal(raw, &m) != nil {
				continue
			}
			if m.Type == "hello" {
				continue // a matching hello draws no reply; see cmd/coordinator
			}
			b, _ := json.Marshal(wire{Type: replyType})
			_, _ = peer.WriteTo(b, src)
		}
	}()
	return ln.LocalAddr().String()
}

// silentCoordinator binds a socket and never answers anything — genuinely unreachable
// as far as the client can tell, which is the condition mesh-walk exists for.
func silentCoordinator(t *testing.T) string {
	t.Helper()
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.LocalAddr().String()
}

func unroutableTestEngine(t *testing.T, addr string) *Engine {
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
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(e.Stop)
	return e
}

// TestListCountriesTellsUnroutableFromSilent is #5's headline. The country-list leg is
// the one the issue names, and after #146 every connect takes it whenever Geo is unset,
// because resolveCountry calls ListCountries.
func TestListCountriesTellsUnroutableFromSilent(t *testing.T) {
	e := unroutableTestEngine(t, unroutableCoordinator(t, "exits"))

	_, err := e.ListCountries(context.Background(), 2*time.Second)
	if err == nil {
		t.Fatal("a coordinator answering with an unroutable type should not produce a country list")
	}
	if errors.Is(err, ErrNoCoordinatorReachable) {
		t.Errorf("a coordinator that ANSWERED was reported as unreachable (%v) — that sentinel triggers mesh-walk, which rediscovers coordinator addresses and cannot help against a protocol disagreement (issue #5)", err)
	}
	if !errors.Is(err, ErrCoordinatorUnroutable) {
		t.Errorf("error = %v; want ErrCoordinatorUnroutable so the call site can tell a version problem from a reachability one", err)
	}
}

// TestListCountriesStillReportsGenuineSilence is the non-vacuity half, and it is what
// stops the fix from disabling mesh-walk altogether. A coordinator that never answers
// must still produce the sentinel — that condition is exactly what warm recovery exists
// for, and losing it would be a worse regression than the bug being fixed.
func TestListCountriesStillReportsGenuineSilence(t *testing.T) {
	e := unroutableTestEngine(t, silentCoordinator(t))

	_, err := e.ListCountries(context.Background(), time.Second)
	if !errors.Is(err, ErrNoCoordinatorReachable) {
		t.Errorf("a coordinator that never answered gave %v; want ErrNoCoordinatorReachable — mesh-walk must still fire when rendezvous really is down", err)
	}
	if errors.Is(err, ErrCoordinatorUnroutable) {
		t.Error("silence was reported as an unroutable answer — nothing was received at all")
	}
}

// TestUnroutableAnswerDominatesSilentMembers: with one member answering unintelligibly
// and another silent, the pool must NOT walk the mesh.
//
// Rendezvous demonstrably works — a member sent us bytes — so the walk would return a
// directory naming coordinators that answer exactly the same way, having torn the engine
// down to get it. This is the same judgement establish already makes for a refusal:
// one member answering is enough to say the network is reachable.
func TestUnroutableAnswerDominatesSilentMembers(t *testing.T) {
	e, err := New(Config{
		Coordinators: []string{silentCoordinator(t), unroutableCoordinator(t, "exits")},
		Roles:        []string{RoleClient},
		SocksAddr:    "127.0.0.1:0",
		Geo:          "NL",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()

	_, lerr := e.ListCountries(context.Background(), 4*time.Second)
	if errors.Is(lerr, ErrNoCoordinatorReachable) {
		t.Errorf("one silent member and one that ANSWERED reported %v — a single answering member means rendezvous is up, so this must not be the mesh-walk sentinel", lerr)
	}
	if !errors.Is(lerr, ErrCoordinatorUnroutable) {
		t.Errorf("error = %v; want ErrCoordinatorUnroutable", lerr)
	}
}

// TestConnectTellsUnroutableFromSilent covers the same hole on the connect leg. The
// issue names the country-list leg because that is where it traced the chain to harm,
// but the mechanism is identical: awaitSession waits for a reply that never comes,
// reports pairSilent, and establish concludes every coordinator is unreachable.
//
// Worth closing on both, not just the one named: with Geo set the client skips the list
// leg entirely and goes straight here, so fixing only the list would leave a configured
// client with exactly the original bug.
func TestConnectTellsUnroutableFromSilent(t *testing.T) {
	e := unroutableTestEngine(t, unroutableCoordinator(t, "exits"))

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	err := e.Connect(ctx)
	if err == nil {
		t.Fatal("connecting through a coordinator this build cannot parse should fail")
	}
	if errors.Is(err, ErrNoCoordinatorReachable) {
		t.Errorf("a coordinator that ANSWERED the connect was reported as unreachable (%v) — the mesh-walk trigger (issue #5)", err)
	}
	if !errors.Is(err, ErrCoordinatorUnroutable) {
		t.Errorf("error = %v; want ErrCoordinatorUnroutable", err)
	}
}

// TestNoteUnroutableEmitsADiagnosis pins the log line issue #4 found had zero test
// references, alongside the control flow it now drives. The event is what tells a human
// which of the two conditions they are in; the error tells the code.
func TestNoteUnroutableEmitsADiagnosis(t *testing.T) {
	events := make(chan Event, 64)
	e, err := New(Config{
		Coordinators: []string{unroutableCoordinator(t, "exits")},
		Roles:        []string{RoleClient},
		SocksAddr:    "127.0.0.1:0",
		Geo:          "NL",
		OnEvent:      func(ev Event) { events <- ev },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()

	_, _ = e.ListCountries(context.Background(), 2*time.Second)

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Kind == EventError && strings.Contains(ev.Message, "cannot route") {
				if !strings.Contains(ev.Message, "exits") {
					t.Errorf("the diagnosis does not name the message type it could not route: %q", ev.Message)
				}
				return
			}
		case <-deadline:
			t.Fatal("no diagnosis was emitted for a reply this build could not route — the condition is invisible by construction, so the one line reporting it is the whole difference between a diagnosis and a mystery timeout")
		}
	}
}

// TestUnroutableCountIsPerAttempt: the count a leg compares against must be a snapshot,
// not a running total, or a member that misbehaved once would be treated as answering
// unroutably forever after — including on attempts where it went genuinely silent.
//
// It also pins that the count is separate from the logging memo. The memo fires once per
// message type per member; if the count shared it, a member's second unroutable reply
// would look exactly like silence to the leg waiting on it.
func TestUnroutableCountIsPerAttempt(t *testing.T) {
	l := &coordLink{raw: "test:1"}
	e := &Engine{}

	mark := l.unroutableMark()
	if l.answeredUnroutably(mark) {
		t.Fatal("a fresh mark reports an unroutable answer before anything happened")
	}
	l.noteUnroutable(e, "exits", "unrecognized message type")
	if !l.answeredUnroutably(mark) {
		t.Error("an unroutable reply did not register against the mark taken before it")
	}
	// A repeat of the SAME type is suppressed from the log by the memo, and must still
	// count — that is the whole reason the two are separate.
	next := l.unroutableMark()
	l.noteUnroutable(e, "exits", "unrecognized message type")
	if !l.answeredUnroutably(next) {
		t.Error("a repeat unroutable reply of an already-reported type did not count — the memo bounds LOGGING, not the control-flow signal")
	}
	// And a fresh mark taken after all of it is clean again.
	if after := l.unroutableMark(); l.answeredUnroutably(after) {
		t.Error("a mark taken after the fact still reports an unroutable answer — the signal must be per-attempt, not a running total")
	}
}
