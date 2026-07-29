package main

import (
	"log"

	"github.com/bacchus-vpn/bacchus/core/capacity"
)

// parseLimits turns the operator-facing -max-speed / -monthly-quota /
// -quota-cycle-day flags into the declared limits this node registers with (issue
// #143, ADR-0040).
//
// Every failure here is fatal, deliberately. The alternative — warn and carry on
// uncapped — means an operator who typed "20 Mb/s" instead of "20Mbit" gets a node
// that serves without limit and finds out from their ISP. A volunteer who asked
// for a cap and silently did not get one is the exact harm #143 exists to prevent,
// so a limit that cannot be parsed stops the node rather than being approximated.
// parseForwardPeerRate turns -relay-forward-peer-rate into the per-previous-hop
// pace a forwarding hop applies (issue #25). Same bits/s vocabulary as -max-speed,
// parsed by the same function, and fatal on a typo for the same reason: an
// operator who asked to divide their uplink between neighbours and silently did
// not get it has the problem they were trying to avoid.
func parseForwardPeerRate(s string) capacity.Rate {
	r, err := capacity.ParseRate(s)
	if err != nil {
		log.Fatalf("-relay-forward-peer-rate: %v", err)
	}
	return r
}

func parseLimits(maxSpeed, monthlyQuota string, cycleDay int) capacity.Limits {
	speedCap, err := capacity.ParseRate(maxSpeed)
	if err != nil {
		log.Fatalf("-max-speed: %v", err)
	}
	quota, err := capacity.ParseBytes(monthlyQuota)
	if err != nil {
		log.Fatalf("-monthly-quota: %v", err)
	}
	l := capacity.Limits{SpeedCap: speedCap, MonthlyQuota: quota}
	if quota != 0 {
		// The cycle day only means something with a quota to reset, and Limits.Validate
		// rejects the pair otherwise. The flag's default is 1 rather than 0 so its help
		// text reads honestly, so it is only carried across when a quota is declared.
		l.CycleDay = cycleDay
	}
	if err := l.Validate(); err != nil {
		log.Fatalf("declared limits: %v", err)
	}
	return l
}
