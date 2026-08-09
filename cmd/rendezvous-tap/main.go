// rendezvous-tap is a logging UDP proxy that sits between a client and a
// coordinator and reports WHAT WENT ON THE WIRE.
//
//	go run ./cmd/rendezvous-tap -listen 127.0.0.1:18080 -upstream <coordinator-host>:8080
//	go run ./cmd/node -role client -coordinators 127.0.0.1:18080 -geo NL
//	# …then Ctrl-C the tap and read the report
//
// # Why it exists
//
// bacchus-vpn/bacchus#212 step 2 asks for "a logging UDP proxy between client and
// coordinator, which is the instrument #183 was found with", and no such tool was
// in this repository — the instrument that found the defect was never committed.
// Of that card's six steps, five report that the connect WORKED; this is the only
// one that reports what the bytes were. It has no card of its own and is not a
// feature: it is the missing half of somebody else's test procedure.
//
// #183 is why the difference matters. A 1453-byte `connect` passed every test in
// this tree — both PR CI runs and a combination build — and failed on a real home
// link, because loopback's MTU is 65536 and nothing in a test can see a datagram
// that is too big for a path it does not have. The four things this reports are
// the four things no test here can settle.
//
// # What it asserts, and what it prints
//
// Per client flow, in the order the client sent them:
//
//  1. the FIRST datagram is a STUN Binding Request;
//  2. the SECOND leads with 0x16 — a DTLS handshake record;
//
// and over every datagram in both directions:
//
//  3. none carries the bytes `{"type"`, which is the literal ADR-0059 exists to
//     take off this hop;
//  4. none exceeds the 1232-byte budget, handshake flights included (ADR-0057:
//     1280-byte path floor, minus 40 for an IPv6 header and 8 for UDP).
//
// SIZES, NOT VERDICTS. Every measurement is printed whether or not anything
// failed: counts, totals, the size of every datagram in order, and the largest
// each way rendered back into the IP datagram it needs. The largest this client
// could build measured 756 bytes in a test, and that number appears nowhere in
// this tool — the thing to check against is the budget. A tool that compared
// against last time's figure would call a regression a pass for 476 bytes.
//
// # It is a passive observer
//
// Bytes out equal bytes in, in both directions: nothing is rewritten, reordered,
// dropped or delayed. A tap that alters the flight it measures gives a confident
// wrong answer — and this one's answer is a size, which is precisely the kind of
// answer that can be wrong without looking wrong. tap.go names the four
// mechanisms; tap_test.go's TestTheTapChangesNothing is what proves it, over a
// corpus that includes an empty datagram and one larger than the budget.
//
// It reads no payload it forwards. Datagrams on this hop carry admission
// credentials, device credentials and issuer certs; each one is classified as it
// is forwarded and then dropped, so what the tap holds is a size and a sentence.
// -bytes prints a leading hex prefix when a run needs one, and defaults to off.
//
// # What it is not
//
// It is not a MITM and cannot read the handshake: once the hop is shaped, the
// payload is opaque to anything on the path, which is the entire point. What it
// can see is what a censor's classifier can see — shape, size, and order — which
// is exactly the surface #212 step 2 is about.
//
// It is not a stand-in coordinator either. core/rendezvous.Peer is that, and the
// tap deliberately shares no code with it: an instrument built from the thing it
// measures agrees with that thing's bugs. classify.go's own doc comment says so
// at greater length.
//
// The coordinator sees the TAP's address, not the client's, because a UDP proxy
// is what it is. Nothing on this hop is keyed on the client's source address in a
// way that changes what is sent — a run through the tap and a run direct produce
// the same datagrams — but the coordinator's association table and the
// XOR-MAPPED-ADDRESS in its Binding Success Response will name the tap. The
// client discards that attribute (core/coldstart.LooksLikeBindingSuccess does not
// read it), which is why the substitution is invisible to the flight.
//
// # Exit status
//
//	0  every assertion held
//	1  an assertion did not hold, or the tap faulted — read the report
//	2  usage
//	3  could not listen, or could not resolve the upstream
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const (
	exitOK        = 0
	exitAssertion = 1
	exitUsage     = 2
	exitSetup     = 3

	// defaultBudget is ADR-0057's maxRendezvousPayload: 1280 - 40 - 8. Spelled
	// out rather than imported, for classify.go's reason — the budget is one of
	// the things under test, and an instrument that read it from the code being
	// measured could not notice the code changing it.
	defaultBudget = 1232
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "UDP address to accept the client on — this is what to pass the client as its -coordinators entry. Port 0 picks one and the tap prints it")
	upstream := flag.String("upstream", "", "the real coordinator's SIGNALING host:port, the one the client would otherwise have been pointed at (required)")
	budget := flag.Int("budget", defaultBudget, "per-datagram UDP payload budget in bytes (ADR-0057: a 1280-byte path floor, less 40 for an IPv6 header and 8 for UDP). Lower it to measure against a tighter path; raising it does not make a datagram fit one")
	quiet := flag.Bool("quiet", false, "suppress the line-per-datagram log and print only the report at the end")
	lead := flag.Int("bytes", 0, "print this many leading bytes of each datagram in hex. 0 (the default) prints none: the payloads on this hop carry credentials, and an instrument should not be the thing that writes them to a terminal")
	flag.Usage = usage
	flag.Parse()

	if *upstream == "" {
		flag.Usage()
		os.Exit(exitUsage)
	}

	t, err := newTap(config{
		listen:   *listen,
		upstream: *upstream,
		budget:   *budget,
		quiet:    *quiet,
		lead:     *lead,
		out:      os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "rendezvous-tap: %v\n", err)
		os.Exit(exitSetup)
	}

	fmt.Printf("rendezvous-tap listening on %s, forwarding to %s\n", t.addr(), *upstream)
	fmt.Printf("point the client at it:  -coordinators %s\n", t.addr())
	fmt.Printf("budget %d B per datagram; Ctrl-C for the report\n\n", *budget)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go t.serve()
	<-stop

	// The listening socket is closed first so serve() returns, but the report is
	// taken from what was already recorded: a datagram in flight at the moment of
	// Ctrl-C is one this tool cannot claim to have measured either way.
	_ = t.close()
	rep := t.report()
	rep.print(os.Stdout)
	if !rep.ok() {
		os.Exit(exitAssertion)
	}
	os.Exit(exitOK)
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, `rendezvous-tap — a logging UDP proxy between a client and a coordinator.

It forwards every datagram verbatim in both directions and reports what it saw:
the size of each one, what shape it was, and whether the four things
bacchus-vpn/bacchus#212 step 2 asks about held.

  rendezvous-tap -listen 127.0.0.1:18080 -upstream <coordinator-host>:8080

Then point a client at the tap instead of at the coordinator:

  bacchus-node -role client -coordinators 127.0.0.1:18080 -geo NL

Ctrl-C the tap when the client is done. Exit 0 if every assertion held, 1 if one
did not or the tap itself faulted.

Flags:
`)
	flag.PrintDefaults()
}
