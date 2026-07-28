package core

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/capacity"
)

// Declared node limits on the register wire (issue #143, ADR-0040) — core's half.
//
// The coordinator's half (its own wire copy, and what it does with these fields)
// is in cmd/coordinator/capacity_test.go. The two are pinned to each other by the
// contract test below plus its twin there, which is the only thing standing
// between the two deliberately-duplicated wire structs and a silent drift.

// TestQuotaStateWireContract mirrors cmd/coordinator's test of the same name. The
// literals live in both binaries because the coordinator must not import core's
// transport stack; a rename on either side has to fail a build somewhere, and
// this pair is that somewhere (same reason as TestRelayDispositionWireContract,
// issue #97).
func TestQuotaStateWireContract(t *testing.T) {
	if quotaOK != "ok" || quotaExhausted != "exhausted" {
		t.Fatalf("quota state literals drifted: ok=%q exhausted=%q", quotaOK, quotaExhausted)
	}
	b, err := json.Marshal(wire{Type: "register", Role: "exit", ID: "e1", SpeedCap: 20_000_000, QuotaState: quotaExhausted})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back wire
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.SpeedCap != 20_000_000 || back.QuotaState != quotaExhausted {
		t.Fatalf("declared limits did not round-trip: %s", b)
	}
}

// readRegister reads datagrams from coord until a register arrives (a forwarder
// sends hello first), so these tests can assert what a register actually carries.
func readRegister(t *testing.T, coord *net.UDPConn, d time.Duration) wire {
	t.Helper()
	deadline := time.Now().Add(d)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		_ = coord.SetReadDeadline(deadline)
		n, _, err := coord.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var m wire
		if err := json.Unmarshal(buf[:n], &m); err != nil {
			continue
		}
		if m.Type == "register" {
			return m
		}
	}
	t.Fatal("no register arrived")
	return wire{}
}

// TestRegisterCarriesDeclaredLimits: an operator who declared limits has them
// reach the coordinator.
func TestRegisterCarriesDeclaredLimits(t *testing.T) {
	coord := fakeCoordinator(t)
	eng, err := New(Config{
		Coordinators: []string{coord.LocalAddr().String()},
		Roles:        []string{"relay"},
		Limits:       capacity.Limits{SpeedCap: 20 * capacity.Mbit, MonthlyQuota: 400 * capacity.GB, CycleDay: 17},
		// In-memory quota: this test is about the wire, not about persistence.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	m := readRegister(t, coord, 3*time.Second)
	if m.SpeedCap != uint64(20*capacity.Mbit) {
		t.Errorf("register SpeedCap = %d, want %d", m.SpeedCap, uint64(20*capacity.Mbit))
	}
	if m.QuotaState != quotaOK {
		t.Errorf("register QuotaState = %q, want %q (quota declared but unspent)", m.QuotaState, quotaOK)
	}
}

// TestRegisterOmitsUndeclaredLimits pins the opt-in property end to end: a node
// that declares nothing sends exactly the register it sent before #143 existed, so
// the running fleet is untouched by this change.
func TestRegisterOmitsUndeclaredLimits(t *testing.T) {
	coord := fakeCoordinator(t)
	eng, err := New(Config{Coordinators: []string{coord.LocalAddr().String()}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	m := readRegister(t, coord, 3*time.Second)
	if m.SpeedCap != 0 {
		t.Errorf("register SpeedCap = %d, want 0 for a node declaring no cap", m.SpeedCap)
	}
	if m.QuotaState != "" {
		t.Errorf("register QuotaState = %q, want empty for a node declaring no quota", m.QuotaState)
	}
}

// TestQuotaStateReflectsSpentQuota drives the engine's own quotaState() against a
// real, exhausted Quota — the value registerLoop stamps on every send.
//
// The re-stamping is not cosmetic. The coordinator's register handler REPLACES its
// registry entry wholesale, so a node that exhausts mid-cycle and carries the fact
// only in the register that happened to be in flight would be assignable again 10
// seconds later, forever. registerLoop therefore recomputes this per send rather
// than baking it into its template.
func TestQuotaStateReflectsSpentQuota(t *testing.T) {
	coord := fakeCoordinator(t)
	limits := capacity.Limits{MonthlyQuota: 1000, CycleDay: 17}
	eng, err := New(Config{
		Coordinators:   []string{coord.LocalAddr().String()},
		Roles:          []string{"relay"},
		Limits:         limits,
		QuotaStatePath: filepath.Join(t.TempDir(), "quota.json"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	if got := eng.quotaState(now); got != quotaOK {
		t.Fatalf("quotaState = %q on a fresh quota, want %q", got, quotaOK)
	}
	// Spend it, exactly as the data path would.
	eng.quota.Add(1000, now)
	if got := eng.quotaState(now); got != quotaExhausted {
		t.Errorf("quotaState = %q after the quota was spent, want %q — the coordinator would keep assigning work", got, quotaExhausted)
	}
}

// TestUndeclaredLimitsBuildAnInertEngine: the nil-receiver idiom means a node with
// no declared limits carries no limiter and no quota at all, so meter() is a
// pass-through and the data path is byte-for-byte what it was.
func TestUndeclaredLimitsBuildAnInertEngine(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{"127.0.0.1:1"}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Stop()
	if eng.limiter != nil {
		t.Error("a node declaring no speed cap must build no limiter")
	}
	if eng.quota != nil {
		t.Error("a node declaring no quota must build no quota tracker")
	}
	if got := eng.quotaState(time.Now()); got != "" {
		t.Errorf("quotaState = %q, want empty so the field is omitted from the wire", got)
	}
	// meter must be a pass-through, not a wrapper, when nothing is declared.
	r := eng.meter(readerFunc(func(p []byte) (int, error) { return 0, nil }))
	if _, ok := r.(readerFunc); !ok {
		t.Error("meter wrapped the reader for a node with no declared limits")
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// TestUDPRelayIsMetered is the regression test for the widest hole this lane had:
// the exit's UDP data path bypassed the declared quota AND the speed cap entirely.
//
// exitTerminate returns early for a udpTargetPrefix target (core/forwarder.go), so
// it never reached the meter() wrapping below it, and core/udprelay.go hand-rolls
// its own datagram loop that called accounting's counter but nothing of capacity's.
//
// It was not theoretical or rare — it was most traffic. A client pulling QUIC/HTTP3
// (YouTube, Google, most CDN-fronted sites), DNS, or torrents moved every byte
// unpaced and uncounted, Quota.Exhausted never flipped, registerLoop kept stamping
// quotaOK, and the coordinator kept assigning. A node with `-monthly-quota 400GB`
// would serve arbitrarily far past it — the exact overage bill issue #143 exists to
// prevent, arriving in silence.
//
// The bug also falsified four separate claims in ADR-0040, the design note, RUNNING.md
// and meter()'s own doc, all of which say "the data path" is metered. It is now.
func TestUDPRelayIsMetered(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], addr)
		}
	}()

	const quota = 4000
	q, err := capacity.NewQuota(capacity.Limits{MonthlyQuota: quota, CycleDay: 17}, "", time.Now())
	if err != nil {
		t.Fatalf("NewQuota: %v", err)
	}
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, udpIdleTimeout: 5 * time.Second, quota: q, limiterCtx: context.Background()}
	go e.exitTerminate("", sConn)

	nc, err := clientHandshake(cConn, key.Public, udpTargetPrefix+echo.LocalAddr().String(), nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	defer nc.Close()

	// Push well past the declared quota, one datagram at a time.
	payload := make([]byte, 500)
	for i := 0; i < 40; i++ {
		if err := writeUDPFrame(nc, payload); err != nil {
			break // the relay tore down: what we want, once the quota is spent
		}
		if _, err := readUDPFrame(nc, make([]byte, maxUDPDatagram)); err != nil {
			break
		}
		if q.Exhausted(time.Now()) {
			break
		}
	}

	used := q.Used(time.Now())
	if used == 0 {
		t.Fatal("the UDP relay moved bytes and the quota counted NONE — the whole UDP path is unmetered, so QUIC/DNS/torrents sail past a declared cap")
	}
	if !q.Exhausted(time.Now()) {
		t.Errorf("pushed 20000 bytes through a %d-byte quota and it is not exhausted (used=%s)", quota, used)
	}
}

// TestInvalidDeclaredLimitsRefuseToStart: a misconfigured limit stops the node
// rather than being approximated. An operator who asked for a cap and silently did
// not get one is the exact harm issue #143 exists to prevent.
func TestInvalidDeclaredLimitsRefuseToStart(t *testing.T) {
	// A quota anchored to a day that does not exist in February would silently skip
	// a reset.
	_, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{"relay"},
		Limits:       capacity.Limits{MonthlyQuota: 400 * capacity.GB, CycleDay: 31},
	})
	if err == nil {
		t.Error("New accepted a quota cycle day of 31")
	}
}
