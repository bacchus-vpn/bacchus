// coldstart-probe (old #18 design spike) — a throwaway measurement tool.
//
// It answers the one empirical question the cold-start spike hinges on: does a
// STUN-shaped UDP packet reach a target from this vantage and get a valid reply
// back, with no operator pre-screening? Run it from the in-region vantage against
// a candidate coordinator/STUN endpoint; a reflexive-address reply proves the
// STUN-shaped bootstrap survives the path.
//
// This is deliberately NOT the real bootstrap — it carries no per-user secret and
// does not fetch a directory snapshot. It measures reachability of the disguise,
// which is the riskiest unknown. See docs/design/rendezvous-cold-start.md §6.
//
//	go run ./cmd/coldstart-probe -target HOST:PORT
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	target := flag.String("target", "stun.l.google.com:19302", "STUN/coordinator UDP host:port to probe")
	timeout := flag.Duration("timeout", 3*time.Second, "per-probe response wait")
	count := flag.Int("count", 3, "number of probes to send")
	flag.Parse()

	ua, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve %q: %v\n", *target, err)
		os.Exit(2)
	}
	conn, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %q: %v\n", *target, err)
		os.Exit(2)
	}
	defer conn.Close()

	fmt.Printf("probing %s (%s) with %d STUN binding request(s)\n", *target, ua, *count)
	buf := make([]byte, 1500)
	ok := 0
	for i := 0; i < *count; i++ {
		tx := newTxID()
		start := time.Now()
		_ = conn.SetDeadline(time.Now().Add(*timeout))
		if _, err := conn.Write(buildBindingRequest(tx)); err != nil {
			fmt.Printf("  #%d send error: %v\n", i+1, err)
			continue
		}
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Printf("  #%d no response (%v)\n", i+1, err)
			continue
		}
		rtt := time.Since(start).Round(time.Millisecond)
		ap, perr := parseBindingResponse(buf[:n], tx)
		if perr != nil {
			fmt.Printf("  #%d reply in %v but unparseable: %v\n", i+1, rtt, perr)
			continue
		}
		ok++
		fmt.Printf("  #%d OK in %v — server sees us as %s\n", i+1, rtt, ap)
	}

	fmt.Printf("\nreachable: %d/%d probe(s) succeeded\n", ok, *count)
	if ok == 0 {
		os.Exit(1) // unreachable from this vantage
	}
}
