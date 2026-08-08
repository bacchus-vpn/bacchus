// coordinator-probe establishes which build a deployed coordinator is running by
// PROBING A CAPABILITY, not by reading a version string (issue #205).
//
//	go run ./cmd/coordinator-probe -addr <coordinator-host>:9000
//
// # Why a version string is not enough, which is the whole reason this exists
//
// On 2026-08-07 the live coordinator was found running a commit two waves old. Its
// startup line read `coordinator release 0.1.0 (revision a868e6e3c447)`; a current one
// read `coordinator release 0.1.0 (revision abe9880ebf17)`. **`release=0.1.0` is true
// in both.** Only the revision separates them, the revision is not on any wire, and
// the obvious check — confirm the releases match — returns a clean answer either way.
// A check that cannot fail is not a check.
//
// So this tool asks the deployment to DO something only a current build can do, and
// reports what happened. Nothing it prints is taken from a self-report.
//
// # The capability, and why it is this one
//
// One bare STUN Binding Request to the coordinator's SIGNALING port (`-addr`, the port
// nodes and clients speak to; not `-turn-addr`). A build carrying issue #175 slice 1
// and issue #202 answers it in place — see cmd/coordinator's answerSTUN, which calls
// coldstart.BindingResponse. A build predating them has no such branch: the datagram
// falls through to json.Unmarshal, fails to decode, and is dropped in silence.
//
// The reply is 40 bytes over IPv4 (20 header + 12 XOR-MAPPED-ADDRESS + 8 FINGERPRINT)
// or 52 over IPv6, and carries those two attributes and nothing else. All of that is
// checked, because "answered" and "answered the way this coordinator answers" are
// different claims.
//
// # The negative control, without which a green result means nothing
//
// A Binding Request is the most ordinary datagram on the internet, and plenty of
// things answer one. Two of them are on the very host being probed: the coordinator's
// own STUN/TURN service on `-turn-addr` answers with byte-identical bytes, on purpose
// (ADR-0060 — two ports on one host answering differently would be a distinguisher),
// on EVERY build this project has ever shipped. **Point this tool at the TURN port and
// it goes green against a coordinator of any age.** That is the false pass this design
// has to rule out, and a shape check cannot do it, because the shapes are identical by
// construction.
//
// So the probe first establishes that it is talking to a Bacchus SIGNALING port at all,
// with a question only that port answers and which every build answers: a `hello` whose
// protocol version cannot match, which draws a `reject` (issue #8, core/handshake).
// That control is deliberately OLD — it has been answered since long before the
// capability existed — so it separates "stale build" from "wrong address" instead of
// moving with the thing being measured.
//
// Four outcomes, and each is a different instruction to the operator:
//
//	control ok, capability ok       exit 0  the deployment carries the shaped rendezvous hop
//	control ok, capability ABSENT   exit 1  a stale build, or -rendezvous-dtls=false
//	control ABSENT, capability ok   exit 4  something else answers here (the TURN port?) — NOT a pass
//	neither                         exit 3  wrong address/port, firewall, or nothing running
//
// The two negative controls confirmed on real hardware are a coordinator predating
// #175 slice 1 (silence) and a current one started `-rendezvous-dtls=false` (also
// silence, and the flag's help text explains why that is a removal rather than a
// downgrade). Both land as exit 1, which is the same instruction: this box is not
// serving the shape a current client speaks.
//
// # What this tool deliberately does not do
//
// It does not report the deployed REVISION — no wire carries it, and inventing one from
// a self-report would put back exactly the field this exists to stop trusting. Pairing a
// commit to a running coordinator is the pin procedure's job (deploy/bacchus-pin.sh);
// this answers the narrower question a pin needs afterwards, which is whether the
// capability the pinned commit introduced is actually being served.
//
// It also carries no credential and asks for nothing privileged: a bare Binding Request
// and a deliberately-invalid hello, both of which any host on the internet may send.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/bacchus-vpn/bacchus/core/handshake"
)

// Exit codes. Distinct rather than "0 or not", because the three failures need three
// different actions and a wrapper script should not have to parse prose to tell them
// apart. Kept as named constants so the doc comment above and the code cannot drift.
const (
	exitCurrent      = 0
	exitStale        = 1
	exitUsage        = 2
	exitUnreachable  = 3
	exitNotSignaling = 4
)

func main() {
	addr := flag.String("addr", "", "coordinator SIGNALING host:port — the -addr the coordinator serves nodes and clients on, NOT -turn-addr (required)")
	timeout := flag.Duration("timeout", 3*time.Second, "how long to wait for each reply")
	attempts := flag.Int("attempts", 3, "how many times to send each probe before concluding silence (UDP loses datagrams; one lost reply must not read as a stale build)")
	control := flag.Bool("control", true, "run the signaling-port control before judging the capability. Turning this off removes the only thing that separates a stale coordinator from the wrong port, and the verdict says so")
	flag.Usage = usage
	flag.Parse()

	if *addr == "" {
		flag.Usage()
		os.Exit(exitUsage)
	}
	if *attempts < 1 {
		fmt.Fprintln(os.Stderr, "coordinator-probe: -attempts must be at least 1")
		os.Exit(exitUsage)
	}

	ua, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coordinator-probe: resolve %q: %v\n", *addr, err)
		os.Exit(exitUsage)
	}
	conn, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		fmt.Fprintf(os.Stderr, "coordinator-probe: dial %q: %v\n", *addr, err)
		os.Exit(exitUsage)
	}
	defer conn.Close()

	fmt.Printf("probing %s (%s)\n", *addr, ua)
	f := run(conn, *control, *attempts, *timeout, os.Stdout)
	code, line := verdict(f, *control)
	fmt.Printf("\n%s\n", line)
	os.Exit(code)
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "coordinator-probe — is the deployed coordinator running a build that carries the shaped rendezvous hop?\n\n")
	fmt.Fprintf(out, "usage: coordinator-probe -addr <coordinator-host>:<signaling-port>\n\n")
	flag.PrintDefaults()
	fmt.Fprintf(out, "\nExit codes: 0 current · 1 stale (or -rendezvous-dtls=false) · 2 usage · 3 unreachable · 4 answered, but this is not a signaling port\n")
}

// findings is what one run learned. Every field is an observation; nothing here is a
// conclusion, which is verdict's job.
type findings struct {
	// ControlAnswered is true when a `reject` came back for the deliberately
	// mismatched hello — i.e. this really is a Bacchus signaling port.
	ControlAnswered bool
	// ControlReason is the reject reason, which names the coordinator's own protocol
	// version. Reported because it is free and occasionally the answer.
	ControlReason string
	// STUNAnswered is true when a valid Binding Success Response came back for OUR
	// transaction id.
	STUNAnswered bool
	STUNReply    bindingReply
	// STUNMalformed records a reply that arrived and did not check out. Distinct from
	// silence: silence is a build without the branch, and a malformed answer is
	// something else on the port.
	STUNMalformed error
}

// run performs both tests on one already-connected UDP socket and narrates as it goes.
//
// One socket for both, deliberately: it is the same 5-tuple a real client uses for its
// connectivity check and its signaling, so a middlebox or a NAT that would break the
// real thing breaks this too rather than being routed around.
func run(conn *net.UDPConn, control bool, attempts int, timeout time.Duration, out io.Writer) findings {
	var f findings

	if control {
		fmt.Fprintf(out, "\ncontrol — is this a Bacchus signaling port? (a hello no build can accept must draw a reject)\n")
		for i := 1; i <= attempts; i++ {
			reason, err := sendHello(conn, timeout)
			if err != nil {
				fmt.Fprintf(out, "  #%d %v\n", i, err)
				continue
			}
			f.ControlAnswered, f.ControlReason = true, reason
			fmt.Fprintf(out, "  #%d reject: %s\n", i, reason)
			break
		}
		if !f.ControlAnswered {
			fmt.Fprintf(out, "  no reject after %d attempt(s)\n", attempts)
		}
	} else {
		fmt.Fprintf(out, "\ncontrol — SKIPPED (-control=false)\n")
	}

	fmt.Fprintf(out, "\ncapability — does the signaling port answer a bare STUN Binding Request? (#175 slice 1, #202)\n")
	for i := 1; i <= attempts; i++ {
		start := time.Now()
		reply, err := sendBinding(conn, timeout)
		switch {
		case err == nil:
			f.STUNAnswered, f.STUNReply = true, reply
			shape := "exactly XOR-MAPPED-ADDRESS + FINGERPRINT"
			if !reply.ExactShape {
				shape = "PARSEABLE BUT NOT THIS COORDINATOR'S SHAPE — it carries more than the two attributes ADR-0060 sends"
			}
			fmt.Fprintf(out, "  #%d answered in %v — %d bytes, %s; it sees us at %s\n",
				i, time.Since(start).Round(time.Millisecond), reply.Len, shape, reply.Reflexive)
		case errors.Is(err, errSilence):
			fmt.Fprintf(out, "  #%d no reply within %v\n", i, timeout)
			continue
		default:
			f.STUNMalformed = err
			fmt.Fprintf(out, "  #%d a reply arrived and did not check out: %v\n", i, err)
		}
		break
	}
	if !f.STUNAnswered && f.STUNMalformed == nil {
		fmt.Fprintf(out, "  silence after %d attempt(s)\n", attempts)
	}
	return f
}

// verdict turns observations into the one sentence an operator acts on, plus the exit
// code a script acts on.
func verdict(f findings, control bool) (int, string) {
	switch {
	case !control:
		if f.STUNAnswered {
			return exitCurrent, "CAPABILITY PRESENT, PORT UNCONFIRMED — the Binding Request was answered, but -control=false means nothing\n" +
				"ruled out that this is the coordinator's TURN port or an unrelated STUN server, both of which answer\n" +
				"identically on every build. Re-run with the control before treating this as a pass."
		}
		return exitStale, "NO ANSWER, PORT UNCONFIRMED — with -control=false there is no way to tell a stale coordinator\n" +
			"from a wrong address. Re-run with the control."
	case f.ControlAnswered && f.STUNAnswered:
		if !f.STUNReply.ExactShape {
			return exitCurrent, "CURRENT, WITH A CAVEAT — this is a Bacchus signaling port and it answered the Binding Request,\n" +
				"but the reply is not the exact shape cmd/coordinator sends (ADR-0060: XOR-MAPPED-ADDRESS and\n" +
				"FINGERPRINT, nothing else). Something may be rewriting it on the path. Worth a look."
		}
		return exitCurrent, "CURRENT — this is a Bacchus signaling port and it serves the shaped rendezvous hop,\n" +
			"so the deployed build carries #175 slice 1 and #202. It does NOT follow that the box is at\n" +
			"any particular commit: this establishes a capability, and deploy/bacchus-pin.sh establishes the commit."
	case f.ControlAnswered && !f.STUNAnswered:
		return exitStale, "STALE — this IS a Bacchus signaling port (it rejected the hello) and it does NOT answer a\n" +
			"Binding Request, so the running build predates #175 slice 1 / #202 — or it is current and was\n" +
			"started -rendezvous-dtls=false, which removes it from the fleet just as thoroughly (no current\n" +
			"client has a cleartext fallback). Either way: no current client can complete a rendezvous here.\n" +
			"Pin it (deploy/bacchus-pin.sh) and check the coordinator's flags."
	case !f.ControlAnswered && f.STUNAnswered:
		return exitNotSignaling, "NOT A SIGNALING PORT — something answered the Binding Request but nothing answered the hello.\n" +
			"This is what the coordinator's own TURN port looks like, and what an unrelated STUN server looks\n" +
			"like; both answer on every build ever shipped. THIS IS NOT A PASS. Check that -addr names the\n" +
			"coordinator's signaling port and not -turn-addr."
	default:
		return exitUnreachable, "UNREACHABLE — nothing answered either probe, which says nothing about the build. Wrong\n" +
			"address or port, a firewall between here and there, or no coordinator running. Note that\n" +
			"BOTH probes are UDP: a path that drops UDP looks exactly like this."
	}
}

// errSilence distinguishes "nothing came back" — the interesting negative — from a
// reply that arrived and failed a check.
var errSilence = errors.New("no reply")

// sendBinding sends one bare Binding Request and validates the answer against the
// transaction id it just drew.
//
// It reads until the deadline rather than reading once, and skips anything that is
// not STUN at all. Both probes share a socket, so a control reply that arrived after
// its own timeout is sitting in the receive queue; reading once would judge THAT
// datagram and report "a reply arrived and did not check out" for a coordinator whose
// only fault was being slow. Anything that is STUN-shaped but wrong is still returned
// as an error — that one is a real finding.
func sendBinding(conn *net.UDPConn, timeout time.Duration) (bindingReply, error) {
	tx := newTxID()
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return bindingReply{}, err
	}
	if _, err := conn.Write(buildBindingRequest(tx)); err != nil {
		return bindingReply{}, errSilence
	}
	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if err != nil {
			return bindingReply{}, errSilence
		}
		if n < headerLen || binary.BigEndian.Uint32(buf[4:8]) != magicCookie {
			continue // not STUN at all — a late reply to the other probe
		}
		return parseBindingResponse(buf[:n], tx)
	}
	return bindingReply{}, errSilence
}

// sendHello sends a hello no build can accept and reads the reject.
//
// The version is handshake.ProtocolVersion + 1000 rather than a literal, so this stays
// a guaranteed mismatch after a protocol bump on either side — Check rejects in BOTH
// directions (too old and too new), so the only way to get a reject that does not
// depend on which side is newer is to be unmistakably further ahead than anything
// deployed. The magic is the real one on purpose: a bad magic is also rejected, but by
// a branch that runs before any version comparison, so the reason it returns would tell
// us nothing about the coordinator.
func sendHello(conn *net.UDPConn, timeout time.Duration) (string, error) {
	req, err := json.Marshal(map[string]any{
		"type":    "hello",
		"magic":   handshake.Magic,
		"version": handshake.ProtocolVersion + 1000,
	})
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	if _, err := conn.Write(req); err != nil {
		return "", errSilence
	}
	// Reads until the deadline for sendBinding's reason, from the other side: a late
	// Binding Response on the shared socket must not be reported as "the hello reply
	// was not JSON".
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if err != nil {
			return "", errSilence
		}
		if n >= headerLen && binary.BigEndian.Uint32(buf[4:8]) == magicCookie {
			continue // STUN — a late reply to the other probe
		}
		var m struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(buf[:n], &m); err != nil {
			return "", fmt.Errorf("a %d-byte reply arrived that is not JSON", n)
		}
		if m.Type != "reject" {
			return "", fmt.Errorf("expected a reject, got type %q", m.Type)
		}
		return m.Reason, nil
	}
	return "", errSilence
}
