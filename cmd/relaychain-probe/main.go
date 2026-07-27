// relaychain-probe (issue #76 design spike) — a throwaway feasibility demonstrator.
//
// It answers the one question the multi-hop relay-chaining design hinges on before
// any production wiring exists: do nested Noise_NK layers peel exactly one-per-hop,
// so each relay learns only its two neighbours while the innermost client<->exit
// target and admission credential survive the whole chain intact?
//
// It builds a client, k relays, and an exit — each with a real X25519 keypair —
// wires them with in-memory pipes, telescopes the onion with the real flynn/noise
// handshake (already a module dependency; see onion.go), and checks the peel
// property. It is NOT a network reachability test (that needs real nodes, a later
// step) — it validates the cryptographic construction only.
//
// This mirrors cmd/coldstart-probe: a small, dependency-free spike tool that imports
// no core package and wires nothing into production. See
// docs/design/relay-chaining.md §8.
//
//	go run ./cmd/relaychain-probe -hops 3
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/flynn/noise"
)

// A stand-in for the exit's #60/#69 admission credential. In the real system this is
// a signed Credential the client verifies against the admission root (see
// core/exit_admission.go); here it is an opaque token, enough to show the credential
// transits the onion intact and a mismatch is detectable.
var exitAdmissionCred = []byte("admission-cred:exit-authorized")

// hop is one relay or the exit: a keypair, an address other hops dial it by, and a
// one-shot channel on which it reports the single next-hop target it decrypted — the
// evidence of what that hop could see.
type hop struct {
	key     noise.DHKey
	addr    string
	isExit  bool
	inbound string      // who dialed it (for the "what each hop saw" report)
	saw     chan string // the target it peeled (buffered 1)
}

// registry lets a relay dial the next hop *by the address it decrypted*, modelling
// that a hop learns and uses only its successor's address.
var registry = map[string]*hop{}

// dial starts the target hop's handler on one end of a fresh in-memory pipe and
// returns the other end — the probe's stand-in for an outbound TCP dial to a node
// ingress. inbound records who is dialing, for the report.
func dial(addr, from string) (net.Conn, error) {
	h, ok := registry[addr]
	if !ok {
		return nil, fmt.Errorf("no node at %q", addr)
	}
	c1, c2 := net.Pipe()
	h.inbound = from
	go h.serve(c2)
	return c1, nil
}

// serve is the relay/exit forwarding handler — the design's generalization of the
// exit's exitTerminate (docs/design/relay-chaining.md §4.1): run the Noise_NK
// responder with this node's key, read the encrypted target, and either forward to
// the next hop (a relay) or terminate (the exit). It peels exactly one layer.
func (h *hop) serve(inbound net.Conn) {
	defer inbound.Close()

	var cred []byte
	if h.isExit {
		cred = exitAdmissionCred // the exit presents its admission credential in msg2 (#60)
	}
	l, err := acceptResponder(inbound, h.key, cred)
	if err != nil {
		return // a wrong/substituted key fails the handshake here (design §4.3)
	}
	target, err := l.readTarget()
	if err != nil {
		return
	}
	h.saw <- target // this is the ONLY next-hop address this node ever learns

	if h.isExit {
		// Innermost responder: the target is the real destination. A real exit would
		// dial it and splice; the probe has proven the peel, so it just terminates.
		return
	}

	// Intermediate relay: dial the next hop by the address just decrypted and splice
	// the inner ciphertext onward — the relay forwards bytes it cannot read (the
	// deeper layers), so it never sees the destination or the client.
	next, err := dial(target, h.addr)
	if err != nil {
		return
	}
	defer next.Close()
	go func() { _, _ = copyStream(next, l) }() // decrypted inner stream -> next hop
	_, _ = copyStream(l, next)                 // next hop -> re-encrypt back to caller
}

// copyStream is a tiny io.Copy that tolerates the net.Pipe close races at teardown.
func copyStream(dst interface{ Write([]byte) (int, error) }, src interface{ Read([]byte) (int, error) }) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, net.ErrClosed) {
				rerr = nil
			}
			return total, rerr
		}
	}
}

func main() {
	hops := flag.Int("hops", 3, "number of relays between client and exit (1..8)")
	flag.Parse()
	if *hops < 1 || *hops > 8 {
		fmt.Fprintf(os.Stderr, "hops must be 1..8, got %d\n", *hops)
		os.Exit(2)
	}

	if err := run(*hops); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAIL: %v\n", err)
		os.Exit(1)
	}
}

func run(hops int) error {
	const destination = "example.com:443"
	registry = map[string]*hop{} // fresh topology each run (re-runnable under test)

	// Build the chain: `hops` relays, then the exit. Each gets a real keypair.
	chain := make([]*hop, 0, hops+1)
	for i := 0; i < hops; i++ {
		k, err := genKey()
		if err != nil {
			return err
		}
		chain = append(chain, &hop{key: k, addr: fmt.Sprintf("relay-%d", i+1), saw: make(chan string, 1)})
	}
	exitKey, err := genKey()
	if err != nil {
		return err
	}
	chain = append(chain, &hop{key: exitKey, addr: "exit", isExit: true, saw: make(chan string, 1)})
	for _, h := range chain {
		registry[h.addr] = h
	}

	fmt.Printf("relay-chain probe: telescoping a %d-relay onion (client", hops)
	for _, h := range chain {
		fmt.Printf(" -> %s", h.addr)
	}
	fmt.Printf(")\n\n")

	// The client telescopes the onion: a Noise_NK layer to each hop in turn, sending
	// over each layer the address of the *next* hop (or, innermost, the real
	// destination). Each new layer rides inside the previous one, so an intermediate
	// relay only ever transports ciphertext it cannot read. This is the exact
	// construction in docs/design/relay-chaining.md §4.1.
	credVerified := false
	client := func() error {
		base, err := dial(chain[0].addr, "client")
		if err != nil {
			return err
		}
		var cur interface {
			Read([]byte) (int, error)
			Write([]byte) (int, error)
			Close() error
		} = base
		for i, h := range chain {
			var verify func([]byte) error
			if h.isExit {
				verify = func(got []byte) error {
					if string(got) != string(exitAdmissionCred) {
						return errors.New("exit admission credential did not verify")
					}
					credVerified = true
					return nil
				}
			}
			l, err := dialInitiator(cur, h.key.Public, verify)
			if err != nil {
				return fmt.Errorf("handshake to %s: %w", h.addr, err)
			}
			target := destination
			if i < len(chain)-1 {
				target = chain[i+1].addr
			}
			if err := l.sendTarget(target); err != nil {
				return fmt.Errorf("send target to %s: %w", h.addr, err)
			}
			cur = l
		}
		// Tear down the whole stack from the client end; splices unwind by EOF.
		return cur.Close()
	}

	done := make(chan error, 1)
	go func() { done <- client() }()
	select {
	case err := <-done:
		if err != nil {
			return err
		}
	case <-time.After(5 * time.Second):
		return errors.New("timed out building the chain (possible deadlock)")
	}

	// Collect what each hop peeled and verify the property.
	saw := make([]string, len(chain))
	for i, h := range chain {
		select {
		case saw[i] = <-h.saw:
		case <-time.After(2 * time.Second):
			return fmt.Errorf("%s never reported a target", h.addr)
		}
	}

	fmt.Println("what each hop learned (peeling one layer each):")
	for i, h := range chain {
		if h.isExit {
			fmt.Printf("  %-8s inbound=%-8s destination=%-16s admission-cred=%s   [blind to: client]\n",
				h.addr, h.inbound, saw[i], credStatus(credVerified))
		} else {
			fmt.Printf("  %-8s inbound=%-8s next-hop=%-16s [blind to: %s]\n",
				h.addr, h.inbound, saw[i], blindTo(i, hops))
		}
	}
	fmt.Println()

	// Assert the design's two headline properties.
	for i := 0; i < len(chain)-1; i++ {
		want := chain[i+1].addr
		if saw[i] != want {
			return fmt.Errorf("%s saw %q, expected next-hop %q", chain[i].addr, saw[i], want)
		}
	}
	if saw[len(chain)-1] != destination {
		return fmt.Errorf("exit saw %q, expected destination %q", saw[len(chain)-1], destination)
	}
	if !credVerified {
		return errors.New("exit admission credential was not verified end-to-end")
	}

	// No single relay saw both the client and the exit/destination: only relay-1's
	// inbound is the client, and it learned relay-2 (not the exit); only the exit
	// learned the destination, and its inbound is the last relay (not the client).
	if hops >= 2 {
		fmt.Println("property: no single relay saw both the client and the exit/destination  OK")
	} else {
		fmt.Println("note: at 1 hop the single relay sees both endpoints — today's behaviour (design §4.4);")
		fmt.Println("      the no-single-relay-sees-both property is the n>=2 opt-in.")
	}
	fmt.Printf("property: innermost client<->exit target + admission credential survived %d relay(s)  OK\n", hops)
	fmt.Println("\nPASS")
	return nil
}

func credStatus(ok bool) string {
	if ok {
		return "VERIFIED"
	}
	return "NOT-VERIFIED"
}

// blindTo names what relay i (0-based) of an n-relay chain cannot see. A relay sees
// the client only if it is the first hop (i==0) and sees the exit only if it is the
// last hop (i==n-1, its next-hop is the exit); it never sees the destination or the
// content. So relay-1 in a chain of >=2 is blind to the exit but not the client, the
// last relay is blind to the client but not the exit, and any middle relay is blind
// to both — which is the whole point of chaining.
func blindTo(i, n int) string {
	parts := make([]string, 0, 4)
	if i > 0 {
		parts = append(parts, "client")
	}
	if i < n-1 {
		parts = append(parts, "exit")
	}
	parts = append(parts, "destination", "content")
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}
