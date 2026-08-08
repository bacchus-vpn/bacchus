// Bacchus node — multi-role peer.
//
// -role is a comma list of: client, relay, exit. A single node can be all three
// at once (the mesh: a user is also a relay/exit). This binary is a thin wrapper
// that wires command-line flags into the engine in core; all of the behaviour
// lives there.
//
//	exit : id is its X25519 public key (see -exit-key); terminates the client's
//	       end-to-end channel and egresses. Registers {id,country,addr}.
//	relay: registers {id} — this is how a node advertises relay capability
//	       (issue #17). The coordinator then prefers it as a data-plane peer for
//	       relay-mode clients, blind-forwarding each assigned session to the
//	       exit's advertised address, over falling back to its TURN server.
//	client: -list, or -exit-id <pubkey> -> direct-first, then a relayed path —
//	       a Bacchus peer relay when one is available, else TURN; local SOCKS5.
//
// See ../../research/05-network-pairing.md.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

func main() {
	coords := flag.String("coordinators", "localhost:8080", "coordinator UDP host:port; comma-separated for a pool (issue #6)")
	role := flag.String("role", "client", "comma list: client,relay,exit")
	// Two switches rather than one, deliberately — see volunteer.go's package comment.
	// A single -volunteer covering both would let somebody who meant to donate bandwidth
	// accept legal exposure they never read about.
	volunteerRelay := flag.Bool("volunteer-relay", false, "donate this connection as a RELAY alongside your own client use of it (issue #12). You carry other people's traffic encrypted and blind-forwarded: a relay never learns the destination and never sees plaintext, so what this costs you is BANDWIDTH, not exposure. Off by default, and entirely independent of -volunteer-exit — this does NOT make you an exit. Behind a home NAT you serve as a client's FIRST hop, which works without any port forwarding; carrying somebody's MIDDLE hop additionally needs a publicly reachable -relay-ingress. Pair it with -max-speed / -monthly-quota so it costs what you chose")
	volunteerExit := flag.Bool("volunteer-exit", false, "donate this connection as an EXIT alongside your own client use of it (issue #12). Other people's traffic egresses to the internet UNDER YOUR OWN IP AND JURISDICTION: it is your address that appears in the logs of every site they reach, and abuse reports, provider notices, and legal process arrive at you. That is LEGAL EXPOSURE, not bandwidth, and it is why this is a separate switch from -volunteer-relay rather than half of one. Off by default. Requires -advertise (the host:port relays dial) and a persistent -exit-key, both checked at startup")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "client SOCKS5 listen")
	listenAddr := flag.String("listen", ":20000", "exit TCP listen (relay path)")
	advertise := flag.String("advertise", "", "exit: host:port relays dial, e.g. 203.0.113.4:20000")
	country := flag.String("country", "", "exit/relay country tag")
	id := flag.String("id", "", "node id (auto if empty)")
	doList := flag.Bool("list", false, "client: list the countries the coordinator will assign exits in, and quit (issue #146). Pass one to -geo")
	stunURL := flag.String("stun", "stun:stun.l.google.com:19302", "STUN url")
	turnURL := flag.String("turn", "", "TURN url")
	turnUser := flag.String("turn-user", "", "TURN username")
	turnPass := flag.String("turn-pass", "", "TURN password")
	forceRelay := flag.Bool("force-relay", false, "force traffic through TURN")
	exitKey := flag.String("exit-key", "", "exit, and any relay serving -relay-ingress: X25519 static private key (64 hex); the node id becomes its public key. Both publish that id in a signed directory clients cache and authenticate against, so a fresh key per restart makes the node unreachable until a new directory propagates. REQUIRED with -relay-ingress, whatever else -role names — the exit role does not exempt it (issue #103). Without an ingress it is generated when empty, which is fine only for a throwaway exit, whose version of this mistake at least fails loudly and at once")
	dtlsFP := flag.String("dtls-fp", "auto", "DTLS ClientHello fingerprint: auto|chrome|firefox|off")
	iceMDNS := flag.Bool("ice-mdns", false, "emit .local mDNS ICE host candidates instead of raw private IPs (see ADR-0022)")
	transport := flag.String("transport", "webrtc", "session transport: webrtc|reality (issue #16)")
	transportPool := flag.String("transport-pool", "", "client: comma-separated transports to race with per-user failover, e.g. reality,webrtc; first is primary (issue #15). Empty uses the single -transport")
	geo := flag.String("geo", "", "client: the country to egress in, e.g. NL (see -list). This is the ONLY thing a connect names — the coordinator picks which exit inside it you get, and there is no way to ask for a specific exit (issue #146, ADR-0042). Empty lets the client take the first country the coordinator reports as available")
	selectionDir := flag.String("selection-dir", "", "client: directory to persist the pool's learned best path per network+geo (issue #15); empty keeps it in memory")
	realityListen := flag.String("reality-listen", ":443", "reality exit: TCP listen address")
	realityAdvertise := flag.String("reality-advertise", "", "reality exit: host:port clients dial (defaults to -advertise)")
	realitySNI := flag.String("reality-sni", "www.microsoft.com", "reality: the site the exit impersonates — SNI worn on the outer TLS (ADR-0032)")
	realityProbeOrigin := flag.String("reality-probe-origin", "", `reality exit: host:port of the impersonated origin — unauthenticated connections are spliced here (so a prober sees the origin's real chain) and failed inner handshakes reverse-proxied here (issue #62 / ADR-0032); empty defaults to the SNI host on :443, "off" disables (immediate close)`)
	maxSpeed := flag.String("max-speed", "", "exit/relay: the aggregate speed you are WILLING to serve, e.g. 20Mbit / 1.5Gbit (issue #143). Your uplink, your call — this is a limit on what leaves your connection, not a claim about how fast it is. Empty is uncapped (today's behaviour). Over-declaring gains nothing: the coordinator serves min(declared, measured)")
	monthlyQuota := flag.String("monthly-quota", "", "exit/relay: how much of YOUR ISP'S CAP you are willing to spend per billing cycle, e.g. 400GB (issue #143) — your cap, or whatever slice of it you choose to donate. Counted the way your ISP counts: forwarded traffic crosses your line twice (in, then out), so 400GB of cap carries roughly 200GB of user traffic. The node stops serving when it is spent and resumes on -quota-cycle-day. Units are decimal, as an ISP bills them (400GB = 400e9). Empty is unmetered")
	quotaCycleDay := flag.Int("quota-cycle-day", 1, "exit/relay: the day of the month -monthly-quota resets — your ISP BILLING day, not the 1st (issue #143). Range 1..28. Getting this wrong is how a node sails past your real cap mid-cycle and you get the overage bill; check your last invoice")
	quotaState := flag.String("quota-state", "", "exit/relay: file to checkpoint -monthly-quota usage to, so a restart resumes the current cycle instead of minting a fresh month (issue #143). Strongly recommended with -monthly-quota: without it, any crash resets your quota. Empty keeps it in memory only")
	acctDir := flag.String("acct-dir", "", "accounting: directory for co-signed usage receipts (issue #20 stub); empty disables accounting")
	acctInterval := flag.Int("acct-interval", 60, "accounting: seconds per co-signed usage interval")
	admissionCred := flag.String("admission-cred", "", "path to this node's admission credential (issue #42), minted by cmd/admission-issue and attached to register/list/connect. Empty presents none (fine only against a coordinator with admission disabled)")
	admissionPubKey := flag.String("admission-pubkey", "", "client: the admission authority's public key, hex (issue #60). The client verifies each exit's admission credential against it end-to-end and refuses an exit the authority never authorized, even via a hostile coordinator. Overrides the anchor carried in a coldstart invite. Empty does not verify (fail-open). NOTE this flag names a different thing here than it does on bacchus-coordinator: there it is one member of that coordinator's anchored authority SET (repeatable, role-scoped); here it is this client's own single anchor for verifying an exit end-to-end. See ADR-0047.")
	admissionCRL := flag.String("admission-crl", "", "client: path to a signed revocation bundle, minted by cmd/admission-issue -crl (issue #69). The client rejects an exit whose credential appears in it, even if not yet expired, and re-reads this file on an interval to pick up an operator's rotated bundle without a restart (issue #90). Requires -admission-pubkey. Overrides the bundle carried in a coldstart invite. Empty does not check revocation (fail-open)")
	requireCRL := flag.Bool("require-crl", false, "client: refuse to start when an admission anchor is configured (-admission-pubkey, or one carried in a coldstart invite) but no CRL is, instead of the default fail-open-on-revocation (issue #91). Opt-in; guards against a hostile or buggy coordinator stripping the CRL from a v3 invite. Has no effect without an anchor")
	relayAdmissionPubKey := flag.String("relay-admission-pubkey", "", "client: a SECOND, independent admission authority public key, hex (issue #26) — the anchor used to verify each RELAY HOP's admission credential when chaining (-relay-hops 2+), extending the -admission-pubkey end-to-end check from the exit to every intermediate hop. Empty does not verify hops (fail-open), independent of -admission-pubkey: configuring one does not turn on checking for the other. Revocation is checked against the SAME bundle -admission-crl/-admission-crl-path configure; there is no separate flag for it. A hop whose credential fails this check fails the whole chain")
	deviceCredDir := flag.String("device-cred-dir", "", "client: directory to persist this device's own keypair and the device credential + issuer cert issued for it across restarts (issue #50/#51/#53) — a DIFFERENT credential from -admission-cred; see core/devicecred's package doc. Empty means in-memory only: a fresh device identity every restart and nothing to present, ever, so this node connects exactly as one predating #50 does. The credential itself is not obtained here (enrollment is account-service work, tracked separately, issue #9) — this only says where to keep whatever gets provisioned into it")
	courierListen := flag.String("courier-listen", "", "relay/exit: UDP address to serve mesh-walk recovery snapshots on (issue #31, design §4.3). A node caches the coordinator-signed snapshot and hands it, verbatim, to a recovering client that can no longer reach any coordinator — a courier, never an author. Empty disables the courier.")
	courierInvite := flag.String("courier-invite", "", "relay/exit: bacchus1: invite (from cmd/coldstart-issue) the courier uses to fetch and refresh the snapshot it serves; supplies the coordinator address, fetch secret, and snapshot public key. Required with -courier-listen.")
	meshPeers := flag.String("mesh-peers", "", "client: comma-separated peer courier addresses to walk when every coordinator is unreachable (issue #31). A relay/exit from a prior session, running -courier-listen. Empty disables mesh-walk recovery (fail cold, as before).")
	meshProof := flag.String("mesh-proof", "", "client: path to a cached signed snapshot (e.g. cmd/coldstart-bootstrap -cache) presented to peers as proof of prior contact. Required with -mesh-peers.")
	meshPubkey := flag.String("mesh-pubkey", "", "client: coordinator snapshot-signing public key (hex, from cmd/coordinator -print-bootstrap-pubkey), used to verify snapshots recovered via mesh-walk. Required with -mesh-peers.")
	relayHops := flag.Int("relay-hops", 1, "client: how many nodes a RELAYED path is routed through, so no single relay links you to your exit (issue #142, ADR-0038). 1 is the default and is today's behaviour exactly — one relay, which sees both ends. 2+ builds a chain you assemble yourself from the signed directory: you pick your own exit and tell the coordinator only the first hop, so it never learns where you egress unless it colludes with a node in your path (see docs/design/relay-chaining.md on that limit). Max 4 — a higher number is refused, never quietly shortened. Costs a hop of latency and n times the volunteer bandwidth, needs -relay-directory, and DISABLES direct paths, since a direct path carries no chain")
	relayIngress := flag.String("relay-ingress", "", "relay: TCP address to accept onion layers on, so this node can serve as an intermediate hop in someone else's chain (issue #142). It peels one layer and splices to the next node — it never egresses to the internet, and only forwards to nodes named in -relay-directory. Must be publicly reachable (a middle hop is reached by an outbound dial, not a hole-punch). Requires -relay-directory and -exit-key, whatever else -role names: a hop's node id IS its X25519 public key, and clients authenticate hops against the id in the signed directory, so an identity regenerated on each restart makes this node unreachable as a hop until a fresh directory propagates. Empty opens no such port")
	relayFwdPerPeer := flag.Int("relay-forward-max-per-peer", 0, "relay serving -relay-ingress: most forwarded circuits ONE upstream neighbour may hold open here at once (issue #25, ADR-0038 §6). An intermediate hop cannot see the client — that is the point of the onion — so the neighbour that dialed it is the only thing it can meter, and one neighbour's traffic shares one budget. 0 uses the built-in default (32); there is no way to say unlimited, since forwarding is already opt-in behind -relay-ingress. A circuit over the cap is refused outright, never queued, and the client is told so it can try a different hop rather than treat yours as dead")
	relayFwdTotal := flag.Int("relay-forward-max-total", 0, "relay serving -relay-ingress: most forwarded circuits this node will carry in total, across every neighbour (issue #25). 0 uses the built-in default (256). This is the number that bounds what forwarding can cost you; the per-peer cap only decides how it is shared out. A per-peer value above this one is clamped to it, since otherwise one neighbour could hold every slot")
	relayFwdPeerRate := flag.String("relay-forward-peer-rate", "", "relay serving -relay-ingress: pace forwarded traffic per upstream neighbour, e.g. 5Mbit (issue #25). Empty — the default — is unpaced, because your TOTAL forwarding bandwidth is already bounded by -max-speed; this only divides that budget between neighbours, and is what you reach for when one of them crowds out the rest. Unlike the circuit caps, bytes are slowed rather than dropped: a circuit already admitted is not worth destroying mid-copy to save bandwidth that pacing reclaims anyway")
	relayDirectory := flag.String("relay-directory", "", "path to a coordinator-signed snapshot (e.g. cmd/coldstart-bootstrap -cache) used for relay chaining: a client picks its hops out of it, a -relay-ingress hop admits a forward only to an address in it. Verified against -mesh-pubkey and must be unexpired. Required by -relay-hops 2+ and by -relay-ingress. Re-read from this same path on an interval (issue #27), so an operator rotating the file in place is picked up without a restart — a bad, expired, or unreadable reload leaves the previous directory enforcing unchanged")
	// The signed release channel (issue #34, ADR-0052, ADR-0065). See update.go for
	// why a node polls and a client does not.
	upd := registerUpdateFlags()
	// The account service this node enrolls and renews its device credential
	// against (issue #170, ADR-0071). See enroll.go for why the claim code is not
	// a flag.
	acct := registerAccountFlags()
	flag.Parse()

	// BEFORE anything else: if a previous START of an applied release never
	// confirmed it, put the previous binary back and exit so the supervisor starts
	// it. This start is that release's trial when it is the first one (ADR-0069).
	// Unconditional — the marker was written by a run that may have been configured
	// differently — and with no marker it is one stat.
	updTarget := updateTarget(*upd.target)
	if updTarget != "" {
		checkStartupDemotion(updTarget)
	}

	// One-shot enrollment (issue #170, ADR-0071): redeem a claim code for this
	// node's first device credential and quit. It runs before every other startup
	// check because it PROVISIONS rather than runs — a node being enrolled needs
	// no exit key, no advertise address and no reachable coordinator, and a
	// volunteer misconfiguration should not stand between an operator and a
	// credential.
	if *acct.enroll {
		if err := runEnrollment(context.Background(), acct, *deviceCredDir); err != nil {
			log.Fatal(err)
		}
		return
	}

	// The volunteer opt-ins (issue #12) add serve roles to whatever -role names, and
	// are checked before anything registers: a donation that cannot work must stop the
	// node here, not register as an exit no client can ever be routed to.
	volunteer := volunteerRoles{relay: *volunteerRelay, exit: *volunteerExit}
	limits := parseLimits(*maxSpeed, *monthlyQuota, *quotaCycleDay)
	warnings, err := validateVolunteer(volunteerCheck{
		roles:          volunteer,
		advertise:      *advertise,
		exitKeyHex:     *exitKey,
		relayIngress:   *relayIngress,
		limitsDeclared: limits.SpeedCap != 0 || limits.MonthlyQuota != 0,
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, w := range warnings {
		log.Printf("warning: %s", w)
	}
	if volunteer.any() {
		log.Printf("volunteering: %s", volunteer)
	}
	roles := resolveRoles(*role, volunteer)

	// Load the admission credential once, up front, so a bad path fails loudly
	// here rather than being silently rejected by the coordinator later.
	var admissionCredStr string
	if *admissionCred != "" {
		b, err := os.ReadFile(*admissionCred)
		if err != nil {
			log.Fatalf("read admission credential %s: %v", *admissionCred, err)
		}
		admissionCredStr = strings.TrimSpace(string(b))
	}
	// The relay-chaining directory (issue #142), read here for the same reason. Its
	// signature, freshness, and usefulness as a hop set are checked inside core.New,
	// so a snapshot that is unsigned, expired, or names no usable hop is a startup
	// failure rather than a node that quietly never chains.
	var relayDir []byte
	var relayDirKey ed25519.PublicKey
	if *relayDirectory != "" {
		b, err := os.ReadFile(*relayDirectory)
		if err != nil {
			log.Fatalf("read relay directory %s: %v", *relayDirectory, err)
		}
		relayDir = b
		// The same coordinator snapshot-signing key mesh recovery uses, taken from the
		// flag directly so chaining works without also configuring couriers.
		pub, err := hex.DecodeString(strings.TrimSpace(*meshPubkey))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			log.Fatalf("-relay-directory requires -mesh-pubkey (the coordinator snapshot-signing key, %d bytes of hex) to verify it", ed25519.PublicKeySize)
		}
		relayDirKey = ed25519.PublicKey(pub)
	}
	// The revocation bundle (issue #69) is read, verified, and — on an
	// interval — reloaded by the engine itself (issue #90), so a bad path
	// fails inside core.New below rather than silently falling open on a
	// typo.

	relayFwdRate := parseForwardPeerRate(*relayFwdPeerRate)

	cfg := core.Config{
		Coordinators:         parseCoordinators(*coords),
		Roles:                roles,
		ID:                   *id,
		SocksAddr:            *socksAddr,
		ListenAddr:           *listenAddr,
		Advertise:            *advertise,
		Country:              *country,
		STUNURL:              *stunURL,
		TURNURL:              *turnURL,
		TURNUser:             *turnUser,
		TURNPass:             *turnPass,
		ForceRelay:           *forceRelay,
		ExitKeyHex:           *exitKey,
		DTLSFingerprint:      *dtlsFP,
		ICEmDNS:              *iceMDNS,
		Transport:            *transport,
		TransportPool:        splitCSV(*transportPool),
		Geo:                  *geo,
		SelectionDir:         *selectionDir,
		RealityListen:        *realityListen,
		RealityAdvertise:     *realityAdvertise,
		RealitySNI:           *realitySNI,
		RealityProbeOrigin:   *realityProbeOrigin,
		AcctDir:              *acctDir,
		AcctIntervalSec:      *acctInterval,
		AdmissionCred:        admissionCredStr,
		AdmissionPubKey:      *admissionPubKey,
		AdmissionCRLPath:     *admissionCRL,
		AdmissionRequireCRL:  *requireCRL,
		RelayAdmissionPubKey: *relayAdmissionPubKey,
		DeviceCredDir:        *deviceCredDir,
		Limits:               limits,
		QuotaStatePath:       *quotaState,
		RelayHops:            *relayHops,
		RelayIngress:         *relayIngress,
		RelayDirectory:       relayDir,
		RelayDirectoryKey:    relayDirKey,
		RelayDirectoryPath:   *relayDirectory,

		RelayForwardMaxPerPeer: *relayFwdPerPeer,
		RelayForwardMaxTotal:   *relayFwdTotal,
		RelayForwardPeerRate:   relayFwdRate,
	}
	// Device-credential renewal through the account service (issue #170,
	// ADR-0071). Nil when none is configured, which core reads as renewal off;
	// a configuration that cannot work is fatal here rather than a node that
	// quietly never renews. Enrollment ships with renewal, per ADR-0046 §6.
	renew, err := setupAccountService(acct, *deviceCredDir, roles)
	if err != nil {
		log.Fatal(err)
	}
	cfg.DeviceRenew = renew
	if limits.SpeedCap != 0 || limits.MonthlyQuota != 0 {
		// Echo the declared limits back at startup. An operator who mistyped "20Mb"
		// for "20Mbit", or who has their billing day wrong, should find out here and
		// not from their ISP a month later.
		log.Printf("declared limits: %s", limits)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	coordList := parseCoordinators(*coords)

	// Mesh-walk courier (issue #31): a relay/exit that serves its cached snapshot to
	// recovering clients. Independent of the engine — it runs for the process
	// lifetime, still serving a last-good snapshot even while the coordinators (and
	// so the client engine below) cannot be reached.
	if *courierListen != "" {
		if err := startCourier(ctx, *courierListen, *courierInvite); err != nil {
			log.Fatal(err)
		}
	}

	// -list is a one-shot: it needs a live coordinator and does not recover.
	if *doList {
		cfg.Coordinators = coordList
		eng, err := core.New(cfg)
		if err != nil {
			log.Fatal(err)
		}
		if err := eng.Start(ctx); err != nil {
			log.Fatal(err)
		}
		defer eng.Stop()
		if !eng.HasRole(core.RoleClient) {
			log.Fatal("-list requires the client role")
		}
		countries, err := eng.ListCountries(ctx, 5*time.Second)
		if err != nil {
			log.Fatal(err)
		}
		if len(countries) == 0 {
			fmt.Println("(no country has a registered exit)")
			return
		}
		// Countries, not exits (issue #146): the coordinator picks the exit inside
		// the country you choose, so an exit list is neither offered nor useful.
		// Pass one of these to -geo.
		fmt.Println("Available countries (use with -geo):")
		fmt.Printf("  %-8s  %-10s  %s\n", "COUNTRY", "EXITS", "STATUS")
		for _, c := range countries {
			status := "available"
			if c.Busy {
				status = "BUSY — every exit there is at capacity or out of quota"
			}
			fmt.Printf("  %-8s  %-10s  %s\n", c.Country, fmt.Sprintf("%d/%d", c.Available, c.Exits), status)
		}
		return
	}

	mesh, err := loadMeshRecovery(*meshPeers, *meshProof, *meshPubkey)
	if err != nil {
		log.Fatal(err)
	}

	// The update check loop, once the node is past every startup failure that would
	// have stopped it. A release that arrives is verified against the anchor, staged
	// beside the binary and published by a rename; nothing here can fail in a way
	// that stops the node serving.
	if updTarget != "" {
		go confirmAfter(ctx, startUpdates(ctx, upd, updTarget), confirmProbation)
	}

	// runNode serves (forwarder) or connects (client) and, for a client with mesh
	// recovery configured, walks known peers for a fresh directory and reconnects
	// when every coordinator is unreachable, instead of failing cold (issue #31).
	if err := runNode(ctx, cfg, coordList, mesh); err != nil {
		log.Fatal(err)
	}
}
