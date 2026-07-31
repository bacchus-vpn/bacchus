// Volunteering this connection back to the network (issue #12) — the desktop
// half of the switch cmd/node got in 8cf741a, and the one thing in this package
// that makes the client SERVE rather than only consume.
//
// # Two opt-ins, not one
//
// Config.VolunteerRelay and Config.VolunteerExit are independent booleans, both
// off by default, and there is deliberately no single "volunteer" field or
// checkbox that turns on both. The two costs are not comparable and must not be
// bundled:
//
//   - A RELAY carries other people's traffic encrypted and blind-forwarded. It
//     never learns the destination and never sees plaintext. What it costs is
//     bandwidth.
//   - An EXIT egresses other people's traffic under this machine's OWN IP and
//     jurisdiction. What it costs is legal exposure, and no amount of spare
//     bandwidth is a substitute for having read that sentence.
//
// One control spanning both means somebody who meant to donate bandwidth accepts
// liability they never read about. cmd/node/volunteer.go makes the bundle
// unsayable with a boolean pair; settings.go does it with two separate
// checkboxes, the exit's disclosure attached to the exit's own control rather
// than to a help page, so the cost is visible at the moment of choosing.
//
// # Why the messages here are sentinels rather than formatted strings
//
// Every error and warning below is a package-level value with FIXED text, and
// none of them interpolate the address or key that caused them. That is a
// translation constraint, not a style preference: settings.go passes err.Error()
// through lang.L, so an error's text IS its translation key (see
// translations_test.go's TestValidationErrorsAreTranslated, and
// ErrRelayChainConfig in connection.go for the same contract already in force).
// A message built with fmt.Errorf around a user-supplied address can never be
// translated, so a Russian-speaking volunteer would read the one set of
// sentences in this window that matters most in English.
//
// Interpolation is no loss here anyway, and this is where the desktop client
// legitimately differs from cmd/node: cmd/node names the address back because
// its operator typed it into a shell that has scrolled away, while this window
// puts the message directly under the field still holding the value. What the
// user needs is why it is wrong and what to type instead.
//
// For the same reason the address classes cmd/node reports separately are
// collapsed here where the FIX is identical: a wildcard, a loopback and a
// link-local address are three different mistakes with one correction ("give the
// address the internet reaches you at"), so they share one sentence. The classes
// that need a different decision from the user — private space, carrier-grade
// NAT, a name instead of an address — stay separate, because each leads
// somewhere else.
//
// # Where this is enforced
//
// PlanVolunteer is the only entry point, and it runs BOTH when the settings
// window saves and again in Controller.connectAsync before core.Config is built
// — the same double-check SanitizePoolOrder gets, and for the same reason: a
// hand-edited config file must not be able to smuggle past a dialog it never
// opened. This lives here rather than in settings.go per ADR-0039's
// Fyne-free/Fyne-touching split, so every decision a wrong answer to which
// produces a broken or mis-described donation is reachable from a unit test with
// no GUI toolchain (volunteer_test.go).
package appstate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/bacchus-vpn/bacchus/core"
)

// ErrVolunteerWhileRouted refuses to serve from a build that routes the whole
// device, which today means the one platform with an enforcement.Enforcer
// (Windows, bacchus#59); [E9] macOS and [E10] Linux are proxy-only and can serve
// now.
//
// This is the refusal that is least obvious and matters most, so it is first.
// When this client routes the device, it installs the OS default route into its
// own TUN and — with the kill-switch armed — flips the outbound default to Block
// behind an allowlist of the coordinators, STUN/TURN, the bypass list and the
// tunnel adapter (clients/internal/enforcement/killswitch_windows.go). A relay
// or exit role in that same process has its forwarding caught by exactly that
// route. Two consequences, and both of them break a promise this feature's whole
// point is to keep:
//
//   - Other people's traffic would leave through this machine's own Bacchus
//     connection and egress at the UPSTREAM exit's address, not at this
//     volunteer's. The disclosure on the exit checkbox — under YOUR own IP and
//     jurisdiction — would simply be false, and false in the direction that
//     matters: somebody would accept a legal exposure they do not actually have
//     while their traffic launders through an exit they do not own.
//   - An advertised exit would be unreachable regardless. The inbound dial
//     arrives on the physical interface, but the reply follows the default route
//     into the TUN, so the handshake never completes. The node would register as
//     an exit and serve nobody — the exact silent under-registration cmd/node's
//     validateVolunteer exists to refuse.
//
// So the honest answer is that this client can serve while it is a proxy and
// cannot serve while it is the tunnel, and it says so instead of shipping a
// toggle that quietly means something else. Making enforcement carve the served
// roles' own egress out of the tunnel it installs is real work in
// clients/internal/enforcement rather than a flag here.
var ErrVolunteerWhileRouted = errors.New("Volunteering cannot run while Bacchus routes this whole device. Other people's traffic would leave through your own Bacchus connection instead of under your own address, and an exit you advertised would be unreachable — so the donation would not be what it says it is.")

// ErrVolunteerExitNeedsAddress is the exit opt-in with nothing to advertise.
// core.New refuses this outright ("core: exit role requires Advertise
// host:port") and there is no default it could take, so without this the connect
// fails at construction with a message naming a core field the user never saw.
var ErrVolunteerExitNeedsAddress = errors.New("Exiting for other people needs the address relays dial to reach you: your public address and a port forwarded to this computer, like 203.0.113.4:20000.")

// ErrVolunteerAddressForm covers every way the advertised endpoint is not a
// dialable host:port at all — not host:port, a port that is not a number in
// 1..65535, or a bare port with no host. One sentence for all of them: they are
// the same typing mistake, and the commonest way to make it is pasting the
// address this machine LISTENS on instead of the one the internet reaches it at.
var ErrVolunteerAddressForm = errors.New("That is not an address and port a relay can dial. Give both, like 203.0.113.4:20000 — the address the internet reaches you at, and the port forwarded to this computer.")

// ErrVolunteerAddressUnreachable covers wildcard, loopback and link-local
// addresses: three different mistakes with one correction, so one sentence (see
// this file's doc on the collapse). None of them can be dialed from another
// machine no matter what the network does, which is why they are refused rather
// than warned about — registering one is a guaranteed exit that serves nobody.
var ErrVolunteerAddressUnreachable = errors.New("That address cannot be reached from another computer — it means \"this machine only\", or does not route past your own network. Give the address the internet reaches you at.")

// ErrVolunteerExitNeedsKey is the exit opt-in with no persistent identity. An
// exit's node id IS its X25519 public key, so core generating a fresh one at
// every start (exitStaticKey does, when ExitKeyHex is empty) means a new
// identity at every start while the signed directory clients cache still names
// the old one: unreachable until a new directory propagates, after every
// restart. Refused rather than defaulted, exactly as cmd/node refuses it — and
// unlike cmd/node, the user is offered a generated one instead of a shell
// command (NewExitKeyHex).
var ErrVolunteerExitNeedsKey = errors.New("Exiting for other people needs a permanent identity key, or your exit changes identity at every restart and other people stop being able to reach it. Use Generate to make one, and keep it.")

// ErrVolunteerExitKeyForm mirrors core's own ExitKeyHex refusal, caught here so
// a mistyped key is a sentence in the dialog rather than a construction error
// from a field the user cannot tell was the cause.
var ErrVolunteerExitKeyForm = errors.New("That is not a valid identity key: it has to be 64 hexadecimal characters. Use Generate to make one.")

// The warn-and-serve cases: what is usually wrong but is legitimately used
// somewhere, so it must not be a refusal. Each is a translation key on the same
// footing as the errors above (settings.go passes these through lang.L too), and
// each names a DIFFERENT decision for the user — which is why these three are
// not collapsed the way the refused address classes are.
const (
	// WarnVolunteerAddressPrivate is the commonest form of the advertise
	// mistake behind a home router: the address on the router's status page is
	// the LAN one. Warned rather than refused because a LAN, a lab, or a
	// tunnelled uplink advertises private space correctly, and refusing those
	// would break working deployments to catch a mistake a warning already
	// names.
	WarnVolunteerAddressPrivate = "That is a private address, so only your own network can dial it. Behind a home router the address to advertise is your public one, with that port forwarded to this computer. Saved anyway — a LAN, a lab, or a tunnelled uplink advertises private space correctly."

	// WarnVolunteerAddressCGNAT is carrier-grade NAT space (RFC 6598): what a
	// residential ISP hands out when it has run out of IPv4 and is NATing its
	// subscribers together behind one public address. It is not covered by
	// net.IP.IsPrivate, and it is the case where somebody who read an address
	// off their own router is most convinced they have a public one — there is
	// no port to forward, because the forwarding would have to happen at the
	// ISP. The relay opt-in genuinely does work here, so the warning says so.
	WarnVolunteerAddressCGNAT = "Your provider is sharing one public address between subscribers (carrier-grade NAT), so the address on your router is not the one the internet sees and there is no port for you to forward. An exit here is very unlikely to be reachable. Carrying traffic as a relay does work behind this, and is probably what you want."

	// WarnVolunteerAddressName is a name rather than an address, and it warns
	// for a reason unrelated to reachability: the coordinator does not resolve
	// it, so it cannot corroborate the name against the address it observes the
	// registration arriving from, and it records the exit as a
	// signaling/data-plane split — which under a -geoip-required posture means
	// the exit is not offered to anyone at all.
	WarnVolunteerAddressName = "That is a name rather than an address. The coordinator does not resolve it, so it cannot confirm your signalling and your traffic come from the same machine, and it may not offer your exit to anyone. Give the address itself if you can."
)

// cgnat is RFC 6598 shared address space. Duplicated from cmd/node/volunteer.go
// rather than shared, for the reason connection.go's file doc already records
// for its own mirrored functions: that file is package main and so is importable
// from nowhere. The cost is paid in the direction that keeps the mirrored
// behaviour ASSERTED (volunteer_test.go covers the same classification table
// cmd/node/volunteer_test.go does) rather than assumed to have been copied
// correctly.
var cgnat = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// VolunteerPlan is one validated choice, in the shape core.Config wants it.
// Controller.connectAsync assigns these four straight across; nothing else in
// this package decides what a volunteer's engine looks like.
type VolunteerPlan struct {
	// Roles is core.Config.Roles: always core.RoleClient — this client is a
	// client whatever else it agrees to be — plus core.RoleRelay and/or
	// core.RoleExit for whichever opt-ins are on. The client role is never
	// REPLACED by a serve role, mirroring cmd/node's volunteer flags adding to
	// -role rather than overriding it: somebody donating their connection is
	// still using it.
	Roles []string

	// Advertise and ListenAddr are core.Config's same-named fields, and empty
	// unless the exit opt-in is on.
	//
	// ListenAddr is DERIVED from Advertise's port rather than configured
	// separately, which is the one place this deliberately does not mirror
	// cmd/node: it takes -listen and -advertise as two independent flags
	// (defaulting -listen to :20000), so the two can disagree, and an exit whose
	// advertised port is not the port it listens on registers something nothing
	// can reach. That mismatch is unrepresentable here — one field, one port,
	// asked for once. core.Config.ListenAddr must be set for the same reason:
	// core hands it to net.Listen unchanged, and an empty address there listens
	// on an OS-assigned port that the advertised one would not match.
	Advertise  string
	ListenAddr string

	// ExitKeyHex is core.Config.ExitKeyHex, empty unless the exit opt-in is on.
	ExitKeyHex string

	// Warnings is the warn-and-serve set above: configurations that are usually
	// a mistake but are legitimately used somewhere, so they are reported and
	// then honored. Order is stable (the order they are checked in) so a test
	// and a status line both read the same way.
	Warnings []string
}

// Serving reports whether this plan makes the client carry anybody else's
// traffic. False for the default, all-off plan, which is what makes "does this
// client serve at all" one question rather than two.
func (p VolunteerPlan) Serving() bool {
	for _, r := range p.Roles {
		if r == core.RoleRelay || r == core.RoleExit {
			return true
		}
	}
	return false
}

// ClearVolunteeringIfRouted turns both volunteer opt-ins off when this build
// routes the whole device, and reports whether it changed anything. Issue #101.
//
// It lives here rather than in settings.go for the reason ADR-0039 gives for
// the split: a wrong answer here produces a config that cannot be saved, and
// "cannot be saved" is a broken config. The window's controls are disabled on
// an enforcing build, and Fyne's Disable() does not clear Checked — so without
// this, a stored opt-in reads back ticked from a control the user cannot
// untick, PlanVolunteer refuses, and the Settings window has no reachable state
// from which any setting can be saved.
//
// What it deliberately does NOT touch is VolunteerAdvertise and
// VolunteerExitKey. #100's argument holds: they are read only for the exit
// role, so keeping them costs nothing, and discarding the identity key would
// turn a volunteer who later returns to a non-enforcing machine into a new node
// that nobody's cached directory can reach.
//
// This is the SAVE path's rule. It is not a relaxation of PlanVolunteer, which
// Controller.connectAsync runs against whatever is on disk and which must keep
// refusing — a hand-edited config saying "serve" on a build that routes the
// device has to fail closed, not be quietly rewritten on the way to a connect.
func ClearVolunteeringIfRouted(cfg Config, deviceRouted bool) (Config, bool) {
	if !deviceRouted {
		return cfg, false
	}
	cleared := cfg.VolunteerRelay || cfg.VolunteerExit
	cfg.VolunteerRelay, cfg.VolunteerExit = false, false
	return cfg, cleared
}

// PlanVolunteer validates cfg's four volunteer fields and returns what they
// contribute to core.Config, or the first refusal.
//
// deviceRouted is Controller.DeviceEnforced() — whether this build routes the
// whole device rather than only a SOCKS port. It is a parameter rather than
// something read from the platform here so this stays a pure function both
// callers and a test can drive; see ErrVolunteerWhileRouted for why serving and
// device-wide routing cannot both be true in one process.
//
// The zero Config plans exactly what this client did before #12: the client role
// alone, no advertise, no key, no warnings, no error. That is the default path
// and it must stay free of every check below, which is why each one is gated on
// an opt-in actually being set rather than on a field being non-empty.
//
// It returns at most one error — the first, in the order below, matching
// cmd/node's validateVolunteer — and any number of warnings:
//
//  1. either opt-in while this build routes the whole device
//  2. the exit opt-in with nothing to advertise
//  3. the exit opt-in with an address no relay could dial
//  4. the exit opt-in with no persistent identity key, or a malformed one
//
// The relay opt-in alone requires nothing, which is the ruling on the validation
// side: demanding an exit's setup of a bandwidth-only donor would put the exit's
// cost on the person who explicitly declined it. Note that this client does not
// offer core.Config.RelayIngress at all, so it never reaches the case cmd/node
// has to check — a relay serving an onion INGRESS needs the same persistent key
// an exit does. Behind a home NAT the realistic relay job is a client's FIRST
// hop, which is reached the way the client itself is and needs no inbound
// listener, no port forwarding and no stable identity; carrying somebody's
// middle hop needs a publicly reachable ingress, and offering that here would
// put an exit's setup burden back onto the relay-only choice.
func PlanVolunteer(cfg Config, deviceRouted bool) (VolunteerPlan, error) {
	plan := VolunteerPlan{Roles: []string{core.RoleClient}}
	if cfg.VolunteerRelay {
		plan.Roles = append(plan.Roles, core.RoleRelay)
	}
	if cfg.VolunteerExit {
		plan.Roles = append(plan.Roles, core.RoleExit)
	}
	if !plan.Serving() {
		return plan, nil
	}
	if deviceRouted {
		return VolunteerPlan{}, ErrVolunteerWhileRouted
	}
	if !cfg.VolunteerExit {
		return plan, nil
	}

	advertise := strings.TrimSpace(cfg.VolunteerAdvertise)
	if advertise == "" {
		return VolunteerPlan{}, ErrVolunteerExitNeedsAddress
	}
	port, warnings, err := classifyAdvertise(advertise)
	if err != nil {
		return VolunteerPlan{}, err
	}

	key := strings.TrimSpace(cfg.VolunteerExitKey)
	if key == "" {
		return VolunteerPlan{}, ErrVolunteerExitNeedsKey
	}
	if !validExitKeyHex(key) {
		return VolunteerPlan{}, ErrVolunteerExitKeyForm
	}

	plan.Advertise = advertise
	plan.ListenAddr = ":" + port
	plan.ExitKeyHex = key
	plan.Warnings = warnings
	return plan, nil
}

// classifyAdvertise checks the endpoint a volunteer exit would register and
// returns the port to listen on, plus any warn-and-serve findings.
//
// This is an address-CLASS check and not a reachability probe. Nothing here
// dials anything, and a node cannot usefully test its own public reachability
// from behind its own NAT: hairpinning makes a self-dial answer yes where the
// internet answers no. What it does catch is the class of addresses that cannot
// be reached from off this machine no matter what the network does — which is
// what somebody who never forwarded a port, or who pasted the listen address,
// ends up registering. Mirrors checkAdvertise in cmd/node/volunteer.go, whose
// classification table volunteer_test.go asserts against.
func classifyAdvertise(advertise string) (port string, warnings []string, err error) {
	host, port, splitErr := net.SplitHostPort(advertise)
	if splitErr != nil {
		return "", nil, ErrVolunteerAddressForm
	}
	// A bare port with no host is the "pasted the listen address" case, and it
	// is a form error rather than an unreachable one: there is no address here
	// to classify at all.
	if host == "" {
		return "", nil, ErrVolunteerAddressForm
	}
	p, convErr := strconv.Atoi(port)
	if convErr != nil || p < 1 || p > 65535 {
		return "", nil, ErrVolunteerAddressForm
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return port, []string{WarnVolunteerAddressName}, nil
	}
	switch {
	case ip.IsUnspecified(), ip.IsLoopback(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "", nil, ErrVolunteerAddressUnreachable
	}
	// Checked before IsPrivate, not after: carrier-NAT space is not private
	// space (net.IP.IsPrivate does not cover 100.64.0.0/10), so the two never
	// both match — the order is for a reader, so the more specific diagnosis
	// sits first.
	if cgnat.Contains(ip) {
		return port, []string{WarnVolunteerAddressCGNAT}, nil
	}
	if ip.IsPrivate() {
		return port, []string{WarnVolunteerAddressPrivate}, nil
	}
	return port, nil, nil
}

// exitKeyHexLen is how long core.Config.ExitKeyHex has to be: a 32-byte X25519
// private key, hex-encoded. Derived from the byte count rather than written as
// 64 so the two cannot drift apart.
const exitKeyHexLen = 2 * 32

// validExitKeyHex mirrors core's exitStaticKey: exactly 32 bytes of hex, which
// is what `openssl rand -hex 32` produces and what NewExitKeyHex generates.
func validExitKeyHex(key string) bool {
	if len(key) != exitKeyHexLen {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

// NewExitKeyHex generates a persistent exit identity key: 32 random bytes, hex,
// exactly what cmd/node's documentation tells an operator to produce with
// `openssl rand -hex 32` and what core.Config.ExitKeyHex decodes.
//
// It exists because the alternative on a desktop is telling somebody to open a
// terminal, and issue #12 is a DISCOVERABILITY card: a donation gated behind a
// shell command is only nominally reachable, which is the same complaint the
// card makes about `-role client,relay,exit`. Any 32 bytes are a valid X25519
// private key here — core clamps them itself (exitKeyFromSeed) — so there is no
// weak value to screen for, and crypto/rand is the only source that would make
// this key worth keeping.
func NewExitKeyHex() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
