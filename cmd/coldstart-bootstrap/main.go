// coldstart-bootstrap is the client-side half of the cold-start bootstrap
// (old #18): given an invite string minted by cmd/coldstart-issue, it
// performs the authenticated STUN-shaped fetch (core/coldstart.Bootstrap),
// verifies the coordinator's signature, prints the resulting directory
// snapshot, and caches it to disk.
//
// This is the manual/scriptable counterpart to what a real client embeds via
// core/coldstart directly — see docs/design/bootstrap-protocol.md for the
// wire format and cmd/coldstart-probe for the earlier reachability-only
// spike this supersedes for the real protocol.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

func main() {
	invite := flag.String("invite", "", "invite string from cmd/coldstart-issue (required)")
	cachePath := flag.String("cache", "", "path to cache the signed snapshot at on success (optional)")
	crlOut := flag.String("crl-out", "", "path to save the invite's revocation bundle at, if it carries one (old #69); feed the result to bacchus-node -admission-crl (optional)")
	timeout := flag.Duration("timeout", 5*time.Second, "bootstrap timeout")
	flag.Parse()

	if *invite == "" {
		fmt.Fprintln(os.Stderr, "usage: coldstart-bootstrap -invite <string> [-cache path] [-crl-out path] [-timeout 5s]")
		os.Exit(2)
	}
	inv, err := coldstart.DecodeInvite(*invite)
	if err != nil {
		log.Fatalf("decode invite: %v", err)
	}
	// Surface the admission anchor (old #60) the invite carries, if any: a real
	// client wires this into core.Config.AdmissionPubKey to verify exits end to
	// end. A v1 invite carries none and the client falls open unless it has the
	// anchor from elsewhere (e.g. the -admission-pubkey override).
	if inv.AdmissionKey != nil {
		fmt.Fprintf(os.Stderr, "invite carries admission anchor %s\n", hex.EncodeToString(inv.AdmissionKey))
	}
	// Surface the revocation bundle (old #69) the invite carries, if any: a
	// real client wires this into core.Config.AdmissionCRL alongside the anchor
	// above. A v1/v2 invite carries none and the client does not check
	// revocation unless it has a bundle from elsewhere (e.g. -admission-crl).
	if len(inv.CRL) != 0 {
		fmt.Fprintf(os.Stderr, "invite carries a revocation bundle (%d bytes)\n", len(inv.CRL))
		if *crlOut != "" {
			if err := os.WriteFile(*crlOut, inv.CRL, 0o600); err != nil {
				log.Fatalf("save CRL to %s: %v", *crlOut, err)
			}
			fmt.Fprintf(os.Stderr, "saved revocation bundle to %s\n", *crlOut)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res, err := coldstart.Bootstrap(ctx, inv.Coordinator, inv.SecretID, inv.Secret, inv.PublicKey)
	if err != nil {
		log.Fatalf("bootstrap against %s: %v", inv.Coordinator, err)
	}

	b, _ := json.MarshalIndent(res.Snapshot, "", "  ")
	fmt.Println(string(b))

	if *cachePath != "" {
		if err := coldstart.SaveCache(*cachePath, res.Signed); err != nil {
			log.Fatalf("save cache: %v", err)
		}
		fmt.Fprintf(os.Stderr, "cached signed snapshot to %s\n", *cachePath)
	}
}
