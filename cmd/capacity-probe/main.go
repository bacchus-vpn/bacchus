// capacity-probe (issue #144 design spike) — what an active speed test can and
// cannot tell you.
//
// It does two things, and the second is the point.
//
//  1. It measures a real TCP throughput between two endpoints. An operator can run
//     it against a peer to learn what their uplink actually does, so they can set
//     cmd/node's -max-speed to a number they did not have to guess. That is a
//     genuine, useful, honest job.
//
//  2. It demonstrates, physically, that the number from (1) CANNOT BE TRUSTED for
//     assignment — because a node that wants to lie only has to recognise the
//     tester. `-demo` runs an honest node and a discriminating one side by side and
//     reports what a probe learns about each. The discriminating node is ~15 lines
//     (see servingNode.rateFor). It is fast to the prober and slow to everyone else,
//     and the probe cannot tell the two nodes apart.
//
// That negative result is what docs/design/node-capacity.md §6.1 rests on, and it is
// why the design has NO TESTER: measurement is serving, and a node's rating is what
// real clients attest it delivered. This tool exists so that argument is a thing you
// can run rather than a thing you have to believe.
//
// Like cmd/relaychain-probe and cmd/coldstart-probe, this is a self-contained spike
// tool: it imports no core package and wires nothing into production.
//
//	go run ./cmd/capacity-probe -demo
//	go run ./cmd/capacity-probe -serve :9999                 # on the node
//	go run ./cmd/capacity-probe -probe 203.0.113.10:9999     # from somewhere else
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/time/rate"
)

const (
	// chunk is the write size on the wire; big enough that syscall overhead does not
	// dominate the measurement, small enough to pace smoothly.
	chunk = 64 * 1024
	// burst matches chunk so the limiter can always satisfy one write.
	burst = chunk
)

func main() {
	demo := flag.Bool("demo", false, "run the honest-vs-discriminating demonstration over loopback and exit")
	serve := flag.String("serve", "", "serve side: TCP address to listen on, e.g. :9999")
	probe := flag.String("probe", "", "probe side: TCP address of a -serve peer to measure against")
	dur := flag.Duration("duration", 5*time.Second, "how long to measure for")
	flag.Parse()

	switch {
	case *demo:
		runDemo(*dur)
	case *serve != "":
		runServe(*serve)
	case *probe != "":
		runProbe(*probe, *dur)
	default:
		flag.Usage()
		fmt.Fprintln(os.Stderr, "\nStart with -demo: it is the part of this tool that answers the design question.")
		os.Exit(2)
	}
}

// servingNode is a node under measurement. cap is what its pipe really does for
// ordinary clients; whitelist is the set of source IPs it treats specially.
//
// A node with an empty whitelist is honest: everyone gets the same rate. A node with
// the prober's IP in its whitelist is the adversary of issue #144 — "fast to the
// tester and throttled to real clients" — and it is a dozen lines. That is the whole
// argument against active probing, in code: this is not a sophisticated attack, it
// is an afternoon's work and it defeats any tester whose address can be learned.
type servingNode struct {
	name      string
	honest    rate.Limit // bytes/s served to whitelisted peers (or to everyone, when honest)
	throttled rate.Limit // bytes/s served to everyone else
	whitelist map[string]bool
}

// rateFor is the entire attack. Fifteen lines, no cryptography, no timing analysis:
// just "do I recognise you?".
func (n *servingNode) rateFor(remote net.Addr) rate.Limit {
	if len(n.whitelist) == 0 {
		return n.honest // nobody is special: this node serves everyone the same
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return n.throttled
	}
	if n.whitelist[host] {
		return n.honest // the tester — put on a show
	}
	return n.throttled // an actual user — give them what they are worth
}

// serveOnce accepts one connection and floods it until the peer hangs up, paced to
// whatever rateFor decided this peer deserves.
func (n *servingNode) serveOnce(ln net.Listener) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	lim := rate.NewLimiter(n.rateFor(c.RemoteAddr()), burst)
	buf := make([]byte, chunk)
	for {
		if err := lim.WaitN(context.Background(), len(buf)); err != nil {
			return
		}
		if _, err := c.Write(buf); err != nil {
			return
		}
	}
}

// measure pulls bytes from addr for d and reports the throughput it saw, plus what
// the measurement cost. The cost line matters as much as the rate: a periodic active
// re-test spends this much, on every node, forever — out of the very quota issue
// #143 exists to protect (design note §6.1, failure 4).
func measure(addr string, d time.Duration) (bitsPerSec float64, got int64, err error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(d + 5*time.Second))

	start := time.Now()
	got, _ = io.Copy(io.Discard, &deadlineReader{c: c, until: start.Add(d)})
	elapsed := time.Since(start)
	if elapsed <= 0 {
		return 0, got, fmt.Errorf("no elapsed time")
	}
	return float64(got) * 8 / elapsed.Seconds(), got, nil
}

// deadlineReader stops a read loop at a wall-clock deadline, which is how the
// measurement is bounded by time rather than by volume.
type deadlineReader struct {
	c     net.Conn
	until time.Time
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if time.Now().After(d.until) {
		return 0, io.EOF
	}
	return d.c.Read(p)
}

func runServe(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	fmt.Printf("serving a flood on %s — run: capacity-probe -probe <this address>\n", ln.Addr())
	n := &servingNode{name: "self", honest: rate.Inf}
	for {
		n.serveOnce(ln)
	}
}

func runProbe(addr string, d time.Duration) {
	bps, got, err := measure(addr, d)
	if err != nil {
		log.Fatalf("probe: %v", err)
	}
	fmt.Printf("measured %s over %v (%s transferred)\n", humanBits(bps), d, humanBytes(got))
	fmt.Println()
	fmt.Println("Two things this number is NOT:")
	fmt.Println("  * a capacity you should trust from someone else's node — see -demo;")
	fmt.Println("  * a property of the node — it is a property of the PATH between these")
	fmt.Println("    two hosts, and your users are not on this path.")
	fmt.Printf("\nIt IS a fine basis for your own -max-speed, if you ran both ends yourself.\n")
}

// runDemo is the spike's evidence. Two nodes with identical pipes — one honest, one
// discriminating — measured by the same probe, then asked what a real client gets.
func runDemo(d time.Duration) {
	const (
		realCap   = 8 * 1024 * 1024 // 64 Mbit/s of actual pipe, in bytes/s
		throttled = 256 * 1024      // 2 Mbit/s: what the liar gives real users
	)
	proberIP := "127.0.0.1"

	nodes := []*servingNode{
		{name: "honest-node", honest: realCap},
		{name: "discriminating-node", honest: realCap, throttled: throttled, whitelist: map[string]bool{proberIP: true}},
	}

	fmt.Printf("Both nodes have the same %s pipe. One of them lies.\n", humanBits(realCap*8))
	fmt.Printf("The prober measures each for %v, then a real client asks what it gets.\n\n", d)
	fmt.Printf("%-22s %18s %18s   %s\n", "node", "probe measures", "real client gets", "verdict")
	fmt.Printf("%-22s %18s %18s   %s\n", "----", "--------------", "----------------", "-------")

	fooled := false
	for _, n := range nodes {
		probed := runOne(n, d, true)
		actual := runOne(n, d, false)

		verdict := "consistent"
		// A probe is fooled when what it measured is materially better than what a real
		// client is given. 2x is a deliberately generous bar: the point is not to tune a
		// threshold, it is that the gap is enormous and the probe cannot see it.
		if probed > 2*actual {
			verdict = "PROBE FOOLED"
			fooled = true
		}
		fmt.Printf("%-22s %18s %18s   %s\n", n.name, humanBits(probed), humanBits(actual), verdict)
	}

	fmt.Println()
	if !fooled {
		fmt.Println("The discriminating node did NOT fool the probe. That is unexpected — the")
		fmt.Println("demo is broken, or the machine is too loaded to measure anything. Re-run.")
		os.Exit(1)
	}
	fmt.Println("Both nodes measured the same. One of them serves users at 1/32 of that.")
	fmt.Println("The probe cannot tell them apart, and no amount of probing will:")
	fmt.Println()
	fmt.Println("  * hiding the prober does not help — its address can be learned, and an")
	fmt.Println("    admitted client can enumerate the network's own nodes with `list`;")
	fmt.Println("  * a bulk flood is recognisable AS a flood even from an unknown source;")
	fmt.Println("  * and the measurement is of the path to the PROBER, not to any user.")
	fmt.Println()
	fmt.Println("This is why docs/design/node-capacity.md §6.1 has no tester at all, and why")
	fmt.Println("core/capacity.Estimator.Seed clamps a probe result to a provisional ceiling")
	fmt.Println("instead of believing it. Measurement is serving: a rating is what real")
	fmt.Println("clients attest a node delivered to THEM, which is the one thing a node")
	fmt.Println("cannot fake by recognising who is asking.")
}

// runOne measures one node once, either as the whitelisted prober or as an ordinary
// client. Both dial from 127.0.0.1, so "whitelisted" is simulated by asking the node
// which rate it would pick — the demo is about the DECISION, not about spoofing a
// source address.
func runOne(n *servingNode, d time.Duration, asProber bool) float64 {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Both ends of this demo are loopback, so the node cannot distinguish them by
	// address here. Stand in for that by handing it the identity directly: a real
	// discriminating node reads it off the connection, as rateFor does.
	shim := &servingNode{name: n.name, honest: n.honest, throttled: n.throttled}
	if !asProber && len(n.whitelist) > 0 {
		shim.honest = n.throttled // this peer is not on the list: it gets the real service
	}
	go shim.serveOnce(ln)

	bps, _, err := measure(ln.Addr().String(), d)
	if err != nil {
		log.Fatalf("measure %s: %v", n.name, err)
	}
	return bps
}

func humanBits(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.1f Gbit/s", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1f Mbit/s", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.1f kbit/s", bps/1e3)
	}
	return fmt.Sprintf("%.0f bit/s", bps)
}

func humanBytes(b int64) string {
	switch {
	case b >= 1e9:
		return fmt.Sprintf("%.2f GB", float64(b)/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.1f MB", float64(b)/1e6)
	}
	return fmt.Sprintf("%d B", b)
}
