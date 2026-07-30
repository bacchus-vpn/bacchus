package enforcement

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeCoordinator is a local duplicate of the one in
// clients/fyne/internal/appstate — test files are not importable across
// packages, and there is no shared wire-format package to import instead
// (core's `wire` and cmd/coordinator's copy are both unexported, which
// ADR-0039 already records as the reason appstate has its own). Kept
// field-for-field identical to both so a wire change breaks all three
// together rather than letting this one drift into testing a protocol
// nothing speaks.

// fakeWire is a local, test-only duplicate of the JSON wire shape core.Engine
// and cmd/coordinator speak (see core/engine.go's own unexported `wire` and
// cmd/coordinator/main.go's independent copy of the same shape) - there is no
// shared package to import it from, since core and cmd/coordinator are
// separate binaries and this wire struct is unexported in both. Field names
// and JSON tags are kept identical to both on purpose.
type fakeWire struct {
	Type    string `json:"type"`
	Role    string `json:"role,omitempty"`
	ID      string `json:"id,omitempty"`
	Country string `json:"country,omitempty"`
	Addr    string `json:"addr,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Session string `json:"session,omitempty"`
	// ExitID is the coordinator's ANSWER on a session mint, naming the exit it chose
	// inside the requested country (issue #146, ADR-0042). It is load-bearing: an
	// exit's id IS its Noise static public key (ADR-0009), so a client that does not
	// receive it cannot bring up the end-to-end channel, and core refuses a mint
	// without one. A client never sends it — a connect names a country.
	ExitID    string            `json:"exitId,omitempty"`
	Countries []fakeWireCountry `json:"countries,omitempty"`
	Cand      json.RawMessage   `json:"cand,omitempty"`
	Cred      string            `json:"cred,omitempty"`
	Reason    string            `json:"reason,omitempty"`
}

// fakeExit is the one exit this fake remembers, from its register. It is registry
// state, not a wire shape — the country reply carries no exit ids at all.
type fakeExit struct {
	ID      string
	Country string
}

// fakeWireCountry mirrors the per-country aggregate a real coordinator answers `list`
// with. It replaced a per-exit list: a client picks a COUNTRY and the coordinator picks
// the exit inside it, so exit ids are neither sent nor needed (issue #146).
type fakeWireCountry struct {
	Country   string `json:"country"`
	Exits     int    `json:"exits"`
	Available int    `json:"available"`
	Busy      bool   `json:"busy"`
}

// fakeCoordinator is a minimal stand-in for cmd/coordinator (a separate
// binary this package cannot import) - just enough of the wire protocol,
// documented in core/engine.go and duplicated independently in
// cmd/coordinator/main.go, for one client-role core.Engine and one exit-role
// core.Engine to find each other and complete a real direct-mode session over
// loopback. It silently ignores the version hello (a matching coordinator
// answers only on mismatch, ADR-0016), remembers the one exit that registers,
// answers "list" with the country it is in, and on "connect" mints a session id
// naming that exit, tells the exit
// to accept it, then blind-relays every offer/answer/candidate between the
// two by session id - understanding none of the payload, exactly like the
// real coordinator's relay path.
type fakeCoordinator struct {
	conn *net.UDPConn

	mu       sync.Mutex
	exit     *fakeExit
	exitAddr *net.UDPAddr
	sessions map[string]*net.UDPAddr // session id -> the client's address
	seq      int
}

func newFakeCoordinator(t *testing.T) *fakeCoordinator {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("fakeCoordinator: listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &fakeCoordinator{conn: conn, sessions: map[string]*net.UDPAddr{}}
	go c.serve()
	return c
}

func (c *fakeCoordinator) addr() string { return c.conn.LocalAddr().String() }

func (c *fakeCoordinator) serve() {
	buf := make([]byte, 65535)
	for {
		n, src, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			return // closed (t.Cleanup)
		}
		var m fakeWire
		if json.Unmarshal(buf[:n], &m) != nil {
			continue
		}
		switch m.Type {
		case "hello":
			// Silent: a matching coordinator answers only on version mismatch (ADR-0016).
		case "register":
			c.mu.Lock()
			c.exit = &fakeExit{ID: m.ID, Country: m.Country}
			c.exitAddr = src
			c.mu.Unlock()
		case "list":
			c.mu.Lock()
			var countries []fakeWireCountry
			if c.exit != nil {
				countries = []fakeWireCountry{{Country: c.exit.Country, Exits: 1, Available: 1}}
			}
			c.mu.Unlock()
			c.send(src, fakeWire{Type: "countries", Countries: countries})
		case "connect":
			c.mu.Lock()
			exitAddr, exit := c.exitAddr, c.exit
			// A connect names a country and the coordinator resolves it to an exit. A
			// connect naming none is refused, exactly as the real coordinator refuses
			// it (refuseNoCountry) — so this fake cannot quietly accept a request
			// shape no coordinator would.
			if exitAddr != nil && exit != nil && m.Country != "" && strings.EqualFold(m.Country, exit.Country) {
				c.seq++
				sid := fmt.Sprintf("s%d", c.seq)
				c.sessions[sid] = src
				c.mu.Unlock()
				c.send(exitAddr, fakeWire{Type: "assign", Session: sid})
				// The mint names the assigned exit: the client keys its end-to-end
				// handshake on it and has no other way to learn it.
				c.send(src, fakeWire{Type: "session", Session: sid, ExitID: exit.ID})
				continue
			}
			c.mu.Unlock()
			c.send(src, fakeWire{Type: "error", Reason: "no-such-country"})
		case "offer", "answer", "candidate":
			c.mu.Lock()
			clientAddr, exitAddr := c.sessions[m.Session], c.exitAddr
			c.mu.Unlock()
			if clientAddr == nil || exitAddr == nil {
				continue
			}
			dst := clientAddr
			if src.String() == clientAddr.String() {
				dst = exitAddr
			}
			c.relay(dst, m)
		}
	}
}

// relay forwards m to dst byte-for-byte in the fields that matter (Type,
// Session, Cand carries the SDP/ICE payload verbatim regardless of Type -
// see core/engine.go's coordSignaler.Send) without decoding what Cand holds,
// exactly like the real coordinator's signaling relay.
func (c *fakeCoordinator) relay(dst *net.UDPAddr, m fakeWire) {
	c.send(dst, fakeWire{Type: m.Type, Session: m.Session, Cand: m.Cand})
}

func (c *fakeCoordinator) send(dst *net.UDPAddr, m fakeWire) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	_, _ = c.conn.WriteToUDP(b, dst)
}
