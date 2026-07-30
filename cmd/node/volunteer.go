package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

// The volunteer switch (issue #12): making it discoverable that a client can also
// donate itself to the network, and keeping the two ways of donating separable.
//
// Donating was reachable only by knowing to write -role client,relay,exit, which
// nobody finds by accident. That is a supply problem rather than a usability one:
// AS-diverse hop selection (issue #23) and chain depth both degrade when the directory
// holds too few distinct relays, so the number of donors is load-bearing on a privacy
// property, not just on capacity.
//
// # Two switches, not one
//
// -volunteer-relay and -volunteer-exit are independent booleans, both off by default,
// and there is deliberately no single -volunteer that turns on both. The two costs are
// not comparable and must not be bundled:
//
//   - A RELAY carries other people's traffic encrypted and blind-forwarded. It never
//     learns the destination and never sees plaintext. What it costs is bandwidth.
//   - An EXIT egresses other people's traffic under the volunteer's OWN IP and
//     jurisdiction. What it costs is legal exposure, and no amount of bandwidth is a
//     substitute for having read that sentence.
//
// One switch spanning both means somebody who meant to donate bandwidth accepts
// liability they never read about. Relay-only is the option most home connections can
// safely take, so it has to be sayable on its own — and a boolean pair is what makes
// the bundle UNSAYABLE rather than merely avoidable, which a comma list in the shape of
// -role's would not.

// volunteerRoles is what the two opt-ins came out as. The zero value is the default:
// a node that uses the network and donates nothing to it.
type volunteerRoles struct {
	relay bool
	exit  bool
}

func (v volunteerRoles) any() bool { return v.relay || v.exit }

// String is the startup line an operator reads back. The exit is never named without
// its cost attached: this line is the last place the choice is visible before the node
// starts carrying traffic under the operator's address.
func (v volunteerRoles) String() string {
	switch {
	case v.relay && v.exit:
		return "relay (bandwidth) + exit (other people's traffic egresses under YOUR IP and jurisdiction)"
	case v.relay:
		return "relay only (bandwidth; this node does NOT egress other people's traffic)"
	case v.exit:
		return "exit (other people's traffic egresses under YOUR IP and jurisdiction)"
	}
	return "nothing"
}

// resolveRoles merges the -role list with the volunteer opt-ins into the role set the
// engine is built with, trimmed and deduped in first-seen order.
//
// The volunteer flags ADD to -role rather than replacing it, so the default -role
// client makes `bacchus-node -volunteer-relay` mean client+relay: somebody who uses the
// network and also donates to it, which is the shape the switch exists to make
// reachable. Naming a role both ways is not an error; it collapses.
func resolveRoles(roleList string, v volunteerRoles) []string {
	roles := splitCSV(roleList)
	seen := map[string]bool{}
	for _, r := range roles {
		seen[r] = true
	}
	for _, add := range []struct {
		on   bool
		role string
	}{{v.relay, core.RoleRelay}, {v.exit, core.RoleExit}} {
		if add.on && !seen[add.role] {
			seen[add.role] = true
			roles = append(roles, add.role)
		}
	}
	return roles
}

// volunteerCheck is the configuration validateVolunteer inspects: the two opt-ins plus
// the flags a donation's usefulness actually depends on.
type volunteerCheck struct {
	roles          volunteerRoles
	advertise      string // -advertise
	exitKeyHex     string // -exit-key
	relayIngress   string // -relay-ingress
	limitsDeclared bool   // -max-speed or -monthly-quota was given
}

// validateVolunteer refuses a donation that cannot work, before the node registers
// anything.
//
// The failure this exists to prevent is the quiet one. A node that registers as an exit
// no relay can dial, or as an exit whose identity changes at every restart, looks
// healthy from the inside: it registers, it logs, it stays up, and it serves nobody. The
// operator finds out never. So what a volunteer needs is checked at startup and stops
// the node, with a message naming the flag that was typed.
//
// These checks hang off the VOLUNTEER flags, not off the roles. -role exit keeps exactly
// today's behaviour, validated only by core.New: it is the raw, expert path, and a lab
// stack that advertises a loopback address on purpose still works unchanged.
// -volunteer-exit is the guided path for somebody donating a home connection, where the
// same configuration is a mistake every time.
//
// It returns at most one error — the first, in the order below — and any number of
// warnings, which cover what is usually wrong but is legitimately used somewhere:
//
//  1. -volunteer-exit without -advertise
//  2. -volunteer-exit with an -advertise no relay could dial
//  3. -volunteer-exit without -exit-key
//  4. -volunteer-relay serving -relay-ingress without -exit-key
func validateVolunteer(c volunteerCheck) (warnings []string, err error) {
	if c.roles.exit {
		if strings.TrimSpace(c.advertise) == "" {
			return nil, errors.New("-volunteer-exit requires -advertise: an exit registers the host:port a relay dials to reach it, and there is no default — without one this node registers as an exit nothing can route to. Give your public address and the port -listen binds, e.g. -advertise 203.0.113.4:20000")
		}
		w, err := checkAdvertise(c.advertise)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, w...)
		if strings.TrimSpace(c.exitKeyHex) == "" {
			return nil, errors.New("-volunteer-exit requires -exit-key: an exit's node id IS its X25519 public key, so a key generated afresh at every start is a new identity at every start, while the signed directory clients cache still names the old one — the node is unreachable until a new directory propagates, after every restart. Generate one once and keep it: `openssl rand -hex 32`")
		}
	}
	// A relay that opted into carrying onion layers is authenticated by clients against
	// the id the signed directory publishes for that hop, exactly as an exit is, so it
	// needs the same stable key for the same reason. core generates one when -exit-key
	// is empty rather than refusing, which for a hop is the silent-identity-churn case
	// again; the volunteer path will not take that default.
	if c.roles.relay && strings.TrimSpace(c.relayIngress) != "" && strings.TrimSpace(c.exitKeyHex) == "" {
		return nil, errors.New("-volunteer-relay with -relay-ingress requires -exit-key: a forwarding hop's node id IS its X25519 public key and clients authenticate the hop against the id in the signed directory, so a key generated afresh at every start makes this node unusable as a hop until a new directory propagates. Generate one once and keep it: `openssl rand -hex 32`")
	}
	if c.roles.any() && !c.limitsDeclared {
		warnings = append(warnings, "volunteering with no declared limits: this node will serve uncapped and unmetered, which on a residential line is how a donation turns into an overage bill. -max-speed caps what leaves your connection and -monthly-quota caps what it spends against your ISP's cap; see docs/RUNNING.md. Serving anyway — uncapped is a legitimate choice on a line you are not billed by volume")
	}
	return warnings, nil
}

// cgnat is RFC 6598 shared address space: what a residential ISP hands out when it has
// run out of IPv4 and is NATing its subscribers together behind one public address. It
// is not covered by net.IP.IsPrivate, and it is the case where an operator who read an
// address off their own router is most convinced they have a public one — there is no
// port to forward, because the forwarding would have to happen at the ISP.
var cgnat = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// checkAdvertise classifies the -advertise endpoint a volunteer exit registers.
//
// This is an address-class check and not a reachability probe. Nothing here dials
// anything, and a node cannot usefully test its own public reachability from behind its
// own NAT: hairpinning makes a self-dial answer yes where the internet answers no. What
// it does catch is the class of addresses that cannot be reached from off this machine
// no matter what the network does — which is what an operator who never forwarded a
// port, or who pasted the -listen value, ends up registering.
//
// Refused outright: a wildcard, loopback, or link-local address, and anything that is
// not a dialable host:port at all. None of them can ever be dialed by a relay on another
// machine, so registering one is guaranteed silent under-registration.
//
// Warned about rather than refused: private and carrier-NAT space. Behind a home router
// the address to advertise is the PUBLIC one, so a 192.168.x.x here is the commonest
// form of the same mistake — but a node reached across a LAN, a lab, or a tunnelled
// uplink advertises private space correctly, and refusing that would be wrong. A name is
// warned about for a different reason: the coordinator will not resolve it, so it cannot
// corroborate the name against the address it observes the register arriving from, and
// it records the exit as a signaling/data-plane split — which under its -geoip-required
// posture means the exit is not offered to anyone at all.
func checkAdvertise(advertise string) ([]string, error) {
	advertise = strings.TrimSpace(advertise)
	host, port, err := net.SplitHostPort(advertise)
	if err != nil {
		return nil, fmt.Errorf("-advertise %q must be host:port — the endpoint a relay dials to reach your exit, e.g. 203.0.113.4:20000 (%v)", advertise, err)
	}
	p, perr := strconv.Atoi(port)
	if perr != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("-advertise %q: %q is not a port a relay can dial (1..65535, numeric)", advertise, port)
	}
	if host == "" {
		return nil, fmt.Errorf("-advertise %q names no host: a relay has to dial an address, and a bare port is the one this node LISTENS on (-listen), not the one the internet reaches it at", advertise)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return []string{fmt.Sprintf("-advertise %s is a name rather than an address: the coordinator does not resolve it, so it cannot check that your signaling and your data plane are the same machine. It records the exit as split, and a coordinator running -geoip-required drops the country entirely — which means your exit is never offered to anyone. Advertise the IP if you can", advertise)}, nil
	}
	switch {
	case ip.IsUnspecified():
		return nil, fmt.Errorf("-advertise %s is a wildcard address: it means \"every interface on this machine\", which says nothing to a relay on another machine that has to dial you. Advertise the address the internet reaches you at", advertise)
	case ip.IsLoopback():
		return nil, fmt.Errorf("-advertise %s is loopback: reachable only from this machine, so no relay can ever dial it and this node would register as an exit that serves nobody. Advertise the address the internet reaches you at", advertise)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return nil, fmt.Errorf("-advertise %s is link-local: it does not route past your own network segment, so no relay can dial it. Advertise the address the internet reaches you at", advertise)
	}
	if ip.IsPrivate() {
		return []string{fmt.Sprintf("-advertise %s is a private address, so only your own network can dial it. Behind a home router the address to advertise is your PUBLIC one, with %s forwarded to this machine. Registering anyway — a LAN, a lab, or a tunnelled uplink advertises private space correctly", advertise, port)}, nil
	}
	if cgnat.Contains(ip) {
		return []string{fmt.Sprintf("-advertise %s is carrier-grade NAT space (RFC 6598): your ISP is sharing one public address between subscribers, the address on your router is not the one the internet sees, and there is no port for you to forward. An exit here is very unlikely to be reachable — relay-only (-volunteer-relay) does work behind CGNAT and is probably what you want. Registering anyway", advertise)}, nil
	}
	return nil, nil
}

// clientEngine is the part of *core.Engine that supervising the client half uses, named
// as an interface so the retry policy is testable without standing up a coordinator, an
// exit, and two WebRTC handshakes.
type clientEngine interface {
	Connect(ctx context.Context) error
	Done() <-chan struct{}
}

// errNodeStopped reports that the node was shut down — an interrupt, a cancelled
// context, or the engine stopping underneath — rather than having failed at anything.
// runNode turns it into a clean exit.
var errNodeStopped = errors.New("node stopped")

// clientHalf supervises the client connect of an already-started engine.
type clientHalf struct {
	eng     clientEngine
	serving bool                            // this node also holds a relay and/or exit role
	meshOn  bool                            // mesh-walk recovery is available to the caller right now
	backoff func(attempt int) time.Duration // wait before retrying, by attempt number
}

// run brings up the client half and returns once it is connected.
//
// For a node that only clients, this is one Connect and the error is the caller's to
// surface: the connect failing IS the node failing, which is today's behaviour exactly.
//
// For a node that also SERVES — the volunteer shape, client plus relay and/or exit in
// one process — a failed client connect is retried against the LIVE engine instead, and
// never surfaced. That engine holds the exit listener, the relay forwarding ingress and
// the coordinator registrations, so returning the error here would end this node's
// contribution to the network because of a fault on its own consumer side. The two
// halves fail for unrelated reasons: "every exit in the country I asked for is busy"
// says nothing whatever about whether this node can still carry other people's traffic.
// Until now that took the whole process down (runNode returned, main called log.Fatal),
// which on a supervised node is a restart loop and on an unsupervised one is a volunteer
// who quietly left the network.
//
// The one failure still handed back for a serving node is all-coordinators-unreachable
// while mesh-walk recovery is available, because rebuilding against coordinators
// rediscovered through a peer beats retrying against addresses that have stopped
// answering. The caller owns that rebuild, and it does briefly drop this node's
// registrations — which is the right trade when the coordinators they were sent to are
// gone.
func (c clientHalf) run(ctx context.Context) error {
	for attempt := 0; ; attempt++ {
		err := c.eng.Connect(ctx)
		if err == nil {
			return nil
		}
		if !c.serving {
			return err
		}
		if c.meshOn && errors.Is(err, core.ErrNoCoordinatorReachable) {
			return err
		}
		if ctx.Err() != nil {
			return errNodeStopped
		}
		wait := c.backoff(attempt)
		log.Printf("client connect failed: %v — retrying in %s. This node keeps serving as %s throughout (issue #12)", err, wait, c.serveDesc())
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return errNodeStopped
		case <-c.eng.Done():
			return errNodeStopped
		}
	}
}

// serveDesc names what stays up across a client-side failure, so the retry line says
// what is still being contributed rather than only what broke.
func (c clientHalf) serveDesc() string {
	if c.serving {
		return "a relay/exit"
	}
	return "a client only"
}

// clientRetryBackoff is how long a serving node waits before retrying its own client
// connect: 15s, doubling to a 10-minute ceiling.
//
// Slow, and capped rather than unbounded. What is being retried is the node's own USE of
// the network, which nobody but its operator is waiting on, while each attempt costs a
// coordinator round trip and — on the pooled path — real dials against every candidate.
// The contribution the node is making in the meantime does not depend on any of it
// succeeding, which is the entire point of retrying here instead of dying.
func clientRetryBackoff(attempt int) time.Duration {
	const (
		base    = 15 * time.Second
		ceiling = 10 * time.Minute
	)
	d := base
	for i := 0; i < attempt && d < ceiling; i++ {
		d *= 2
	}
	if d > ceiling {
		return ceiling
	}
	return d
}
