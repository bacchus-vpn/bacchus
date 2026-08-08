// End-to-end coverage for the verdict this tool exists to produce, over real UDP
// sockets against stand-in coordinators of each age.
//
// The point of testing it this way rather than unit-testing verdict() alone: the
// expensive failure mode is not a wrong sentence, it is a probe that reports CURRENT
// against something that is not a current coordinator, or STALE against one that is.
// Both are properties of the whole path — socket, ordering, timeouts, parser — and
// neither is visible from a table test. Each fake below is a coordinator of a
// particular age, built from the SAME production halves the real one uses
// (coldstart.BindingResponse for the STUN answer, handshake.Check for the reject), so
// what is being asserted is the probe rather than a second copy of the coordinator.
package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/handshake"
)

// fake is a stand-in coordinator. The two booleans are the two eras and the two
// misconfigurations this probe has to tell apart:
//
//	stun=true  hello=true   a current coordinator (#175 slice 1 + #202)
//	stun=false hello=true   a coordinator predating them, or one started -rendezvous-dtls=false
//	stun=true  hello=false  the coordinator's own TURN port, or an unrelated STUN server
//	stun=false hello=false  nothing listening that answers either question
type fake struct {
	stun  bool
	hello bool
	// extra, when set, is appended to the STUN answer so the reply is valid STUN in
	// a shape cmd/coordinator does not send.
	extra []attr
}

// serve binds 127.0.0.1 and answers in the order cmd/coordinator's servePackets does:
// a STUN-shaped datagram is answered in place, and anything else falls through to
// JSON. It returns the address to probe; the socket closes with the test.
func (f fake) serve(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			raw := append([]byte{}, buf[:n]...)
			ap := src.AddrPort()
			from := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())

			if f.stun {
				// The production encoder, exactly as answerSTUN calls it.
				if resp, ok := coldstart.BindingResponse(raw, from); ok {
					if len(f.extra) > 0 {
						resp = encodeResponse([12]byte(raw[8:20]), from, f.extra...)
					}
					pc.WriteToUDP(resp, src)
					continue
				}
			}
			if !f.hello {
				continue
			}
			var m struct {
				Type         string                 `json:"type"`
				Magic        string                 `json:"magic"`
				Version      int                    `json:"version"`
				Capabilities []handshake.Capability `json:"capabilities,omitempty"`
			}
			if json.Unmarshal(raw, &m) != nil || m.Type != "hello" {
				continue
			}
			// The production check, exactly as cmd/coordinator's "hello" case calls it.
			if ok, reason := handshake.Check(handshake.Hello{Magic: m.Magic, Version: m.Version, Capabilities: m.Capabilities}); !ok {
				out, _ := json.Marshal(map[string]any{"type": "reject", "reason": reason})
				pc.WriteToUDP(out, src)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

// probeAgainst dials the fake the way main() dials a real coordinator and runs both
// tests. Short timeouts: every negative here is a deliberate silence, so the test's
// runtime is attempts x timeout and nothing is gained by waiting seconds for it.
func probeAgainst(t *testing.T, addr *net.UDPAddr, control bool) (probeRun, string, int) {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	var out bytes.Buffer
	f := run(conn, control, 2, 250*time.Millisecond, &out)
	code, line := verdict(f, control)
	return probeRun{f, conn.LocalAddr().String()}, out.String() + "\n" + line, code
}

// probeRun pairs the findings with the source address they were gathered from, which
// is what the reflexive address in the reply has to equal.
type probeRun struct {
	findings
	local string
}

func TestVerdict_CurrentCoordinator(t *testing.T) {
	addr := fake{stun: true, hello: true}.serve(t)
	f, out, code := probeAgainst(t, addr, true)
	if code != exitCurrent {
		t.Fatalf("exit %d, want %d (CURRENT)\n%s", code, exitCurrent, out)
	}
	if !f.ControlAnswered || !f.STUNAnswered || !f.STUNReply.ExactShape {
		t.Fatalf("findings %+v\n%s", f, out)
	}
	// The reflexive address must be this probe's own source address. Anything else
	// means the parser produced a plausible number rather than the right one.
	if want := netip.MustParseAddrPort(f.local); f.STUNReply.Reflexive != want {
		t.Errorf("reflexive %s, want this probe's own source %s", f.STUNReply.Reflexive, want)
	}
	if f.ControlReason == "" {
		t.Error("no reject reason captured — the control proved nothing")
	}
}

func TestVerdict_StaleCoordinator(t *testing.T) {
	// A coordinator that speaks the signaling protocol and does not answer STUN:
	// pre-#175-slice-1, or current and started -rendezvous-dtls=false. The two are
	// indistinguishable from outside, which is why one verdict names both.
	addr := fake{stun: false, hello: true}.serve(t)
	f, out, code := probeAgainst(t, addr, true)
	if code != exitStale {
		t.Fatalf("exit %d, want %d (STALE)\n%s", code, exitStale, out)
	}
	if !f.ControlAnswered || f.STUNAnswered {
		t.Fatalf("findings %+v\n%s", f, out)
	}
	if !bytes.Contains([]byte(out), []byte("rendezvous-dtls")) {
		t.Error("the STALE verdict must name -rendezvous-dtls=false as the other cause, or an operator redeploys a box that was already current")
	}
}

// The false pass this whole design exists to prevent: the coordinator's TURN port
// answers a Binding Request with byte-identical bytes, on every build ever shipped.
// Without the control, this is indistinguishable from a current coordinator.
func TestVerdict_TURNPortIsNotAPass(t *testing.T) {
	addr := fake{stun: true, hello: false}.serve(t)
	f, out, code := probeAgainst(t, addr, true)
	if code != exitNotSignaling {
		t.Fatalf("exit %d, want %d (NOT A SIGNALING PORT)\n%s", code, exitNotSignaling, out)
	}
	if f.ControlAnswered || !f.STUNAnswered {
		t.Fatalf("findings %+v\n%s", f, out)
	}
	if code == exitCurrent {
		t.Fatal("a STUN answer alone must never be a pass")
	}
}

func TestVerdict_Unreachable(t *testing.T) {
	addr := fake{}.serve(t) // bound, and answers nothing
	_, out, code := probeAgainst(t, addr, true)
	if code != exitUnreachable {
		t.Fatalf("exit %d, want %d (UNREACHABLE)\n%s", code, exitUnreachable, out)
	}
}

// A reply that is valid STUN but not this coordinator's shape is still a pass — the
// capability is being served — and the caveat has to reach the operator, because the
// likeliest cause is something on the path rewriting it.
func TestVerdict_ExtraAttributeStillPassesWithACaveat(t *testing.T) {
	addr := fake{stun: true, hello: true, extra: []attr{{0x8022, []byte("elsewhere\x00\x00\x00")}}}.serve(t)
	f, out, code := probeAgainst(t, addr, true)
	if code != exitCurrent {
		t.Fatalf("exit %d, want %d\n%s", code, exitCurrent, out)
	}
	if f.STUNReply.ExactShape {
		t.Fatal("ExactShape=true for a three-attribute reply")
	}
	if !bytes.Contains([]byte(out), []byte("CAVEAT")) {
		t.Errorf("the caveat is not in the output:\n%s", out)
	}
}

// -control=false must never print a plain pass. It removes the only thing separating
// a stale coordinator from the wrong port, and a verdict that did not say so would be
// the false green this tool exists to make impossible.
func TestVerdict_ControlOffNeverReadsAsAPlainPass(t *testing.T) {
	addr := fake{stun: true, hello: false}.serve(t)
	_, out, code := probeAgainst(t, addr, false)
	if code != exitCurrent {
		t.Fatalf("exit %d, want %d", code, exitCurrent)
	}
	if !bytes.Contains([]byte(out), []byte("PORT UNCONFIRMED")) {
		t.Errorf("a -control=false pass must say the port is unconfirmed:\n%s", out)
	}
}

// The probe sends a hello no build can accept. If the version it sends were ever
// acceptable, the control would go silent against a healthy coordinator and every
// verdict would become UNREACHABLE.
func TestControlHelloCannotBeAccepted(t *testing.T) {
	ok, reason := handshake.Check(handshake.Hello{Magic: handshake.Magic, Version: handshake.ProtocolVersion + 1000})
	if ok {
		t.Fatal("the probe's hello is ACCEPTED by this build's handshake.Check — it would draw no reject")
	}
	if reason == "" {
		t.Fatal("rejected with an empty reason")
	}
}
