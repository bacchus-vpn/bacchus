// Runtime configuration. No endpoints are compiled into the binary - they load
// from a JSON file next to the executable, or the per-user config directory
// (mirrors the retired Windows client's config.go's precedence; see that file's doc comment
// for why: config lives outside the binary so the same build serves any
// operator's network). Ship bacchus-fyne.config.example.json as a template.
package appstate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Config holds this client's settings. Coordinators/STUN/TURN are the
// connection endpoints, unchanged since the #148 skeleton and still hand-edited
// in the config file - there is no in-app editor for those. Everything from
// AdmissionPubKey down is the user-facing Settings window's surface, edited via
// settings.go and persisted the same way.
//
// Country is the one field belonging to neither group: it is the MAIN window's,
// set by the country picker (issue #16) and written back to this same file the
// moment the user chooses. It is deliberately not in the Settings window — the
// jurisdiction you exit in is the product's headline choice, not a preference to
// go looking for behind a menu.
//
// The admission fields were config-file-only until issue #93: they are a
// security check, and leaving them out did not make this client simpler, it
// made it fail open. They stay readable from the file — an operator scripting a
// deployment should not have to open a dialog — and are now settable in it too.
// #93 is also where the four fields below them arrived. Its finding is worth
// keeping next to the struct they were missing from: ADR-0039's parity bar is
// eight items of ENFORCEMENT, so this client could meet it in full while being
// unable to configure half of what core supports. Adding a field to core is not
// finished until a client can reach it.
type Config struct {
	// Coordinators is the rendezvous pool: one or more coordinator UDP
	// host:port endpoints (issue #6). Required - Controller.Connect has no
	// coordinator to dial without it.
	Coordinators []string `json:"coordinators"`
	STUN         string   `json:"stun"` // stun:host:port
	TURN         string   `json:"turn"` // turn:host:port
	TURNUser     string   `json:"turnUser"`
	TURNPass     string   `json:"turnPass"`

	// Invite is a `bacchus1:` string from cmd/coldstart-issue, and it is what
	// makes every address above LEARNABLE rather than fixed (bacchus#193,
	// ADR-0061). With one, this client fetches the coordinator's signed
	// cold-start directory at each connect and reads the coordinator pool and
	// the account service out of it; without one it uses exactly the addresses
	// in this file, which is what it did before and is a supported deployment.
	//
	// It is what closes the gap ADR-0016 names: every address in this file is
	// static, and a moved coordinator takes this client offline immediately
	// while a moved account service takes it offline about six hours later. The
	// directory is the one artifact that can carry a correction.
	//
	// # It is PER-RECIPIENT and must never ship inside an installer or a template
	//
	// The invite carries a bootstrap secret, and coldstart.LoadMemStore's own
	// doc records that every entry in a coordinator's secrets file is trusted
	// equally — there is no vouch or trust system underneath it. A secret
	// embedded in a downloadable artifact is therefore a secret the censor
	// holds, and holding it is enough to fetch the directory of every entry
	// point in the network. So the accepted price of this field is that a new
	// install needs TWO out-of-band strings rather than one: an invite alongside
	// the claim code. The shipped template carries this key EMPTY, which is a
	// slot and not a credential.
	//
	// Optional, like everything that follows AdmissionPubKey. A malformed one is
	// refused at connect with its own sentence rather than ignored: a typo that
	// silently disabled directory updates would leave the user believing this
	// client follows a moved address when it does not.
	Invite string `json:"invite"`

	// Country is the country to egress in, as an ISO-3166-1 alpha-2 code, and it
	// reaches core.Config.Geo unchanged (via ValidateCountry). Empty is
	// CountryAutomatic: core resolves the country itself and takes the first
	// assignable one the coordinator offers, which is exactly what this client
	// did before it had a picker, so the zero value is pre-#16 behaviour.
	//
	// A country set here is used VERBATIM even when the coordinator says it is
	// busy or does not know it — the connect is refused and the user is told,
	// never rerouted. That is core's rule (pickCountry) and it is the reason the
	// picker shows a country's busy state BEFORE the click rather than
	// substituting after it: silently egressing somebody through a jurisdiction
	// they did not choose is the worst failure available to this project.
	//
	// It is stored here rather than kept in memory for the session because a
	// choice of jurisdiction that resets at every launch is not a choice. The
	// file is written 0600 and already carries a TURN password, an exit identity
	// key and a bypass list naming the sites this user does not tunnel; one
	// country code is not what makes it sensitive.
	Country string `json:"country"`

	// AdmissionPubKey and AdmissionCRLPath mirror the same-named core.Config
	// fields, and mirror what the Windows tray client passed (its main.go set
	// both). They are here because omitting them is not a neutral omission:
	// core treats an unset AdmissionPubKey as fail-open, so the client verifies
	// nothing and accepts any exit it can complete a Noise_NK handshake with.
	//
	// That silently discards the entire point of ADR-0026/#60. Admission
	// verification is the client's END-TO-END backstop against a HOSTILE
	// COORDINATOR — the one check that does not trust the party doing the
	// matchmaking. A coordinator that hands out an exit it controls is exactly
	// the attack it exists to catch, and without this field it succeeds. There
	// was no field to set it, so no config could have turned it on.
	//
	// AdmissionCRLPath is #69's half: a signed, short-TTL revocation bundle, hot
	// reloaded, so a revoked exit is rejected before its credential expires on
	// its own. Meaningless without AdmissionPubKey, and empty means revocation is
	// not checked at all — also fail-open.
	//
	// Both stay OPTIONAL, which matches core, the coordinator, and the Windows
	// client rather than being a choice made here: a deployment with no admission
	// authority configured must still work. The fix is that an operator who HAS
	// an anchor can now use it.
	AdmissionPubKey  string `json:"admissionPubKey"`
	AdmissionCRLPath string `json:"admissionCrlPath"`

	// Bypass, BypassMode, DisableKillSwitch, and DNS mirror the Windows tray client's
	// same-named Config fields (config.go) exactly - same names, same JSON
	// keys, same semantics - and as of bacchus#59 they are live on any
	// platform with an Enforcer: Controller passes them straight into
	// enforcement.Policy, and the same code that always honored them for the
	// Windows tray client honors them here.
	//
	// They were config surface only until then, which is why this comment
	// used to say at length that nothing enforced them. On a platform with no
	// Enforcer yet ([E9] macOS bacchus#36, [E10] Linux bacchus#37) that is
	// still exactly true, and the UI still says so rather than letting a
	// saved "kill-switch: on" imply an armed one - see
	// Controller.DeviceEnforced, which is what settings.go and ui.go ask
	// instead of assuming either answer.
	Bypass            []string `json:"bypass"`
	BypassMode        string   `json:"bypassMode"`
	DisableKillSwitch bool     `json:"disableKillSwitch"`
	DNS               string   `json:"dns"`

	// AutoConnect, when true, has main.go call Controller.Connect once at
	// startup instead of waiting for the user to press the button - useful
	// on a machine where this app itself launches at login (LaunchOnBoot).
	// Unlike Bypass/DisableKillSwitch/DNS above, this is fully functional
	// today: it needs nothing from core or a TUN device, just an extra call
	// in main.go.
	AutoConnect bool `json:"autoConnect"`

	// LaunchOnBoot, when true, registers this binary to start when the user
	// logs in, via the current OS's native mechanism (see autostart_*.go) -
	// also fully functional today, and independent of AutoConnect: a user may
	// want the app available at login without it dialing out immediately, or
	// vice versa.
	LaunchOnBoot bool `json:"launchOnBoot"`

	// TransportPool mirrors core.Config.TransportPool and the Windows tray client's
	// same-named field, JSON key included: a preference-ordered ladder the
	// client races and then converges on, per network (issue #15, ADR-0028).
	// Empty turns the pool off and keeps the single-transport connect, which
	// is what this client did before issue #93 — so the zero value is exactly
	// pre-#93 behaviour.
	//
	// Whatever is saved here is restricted to the tunnel-safe set
	// (SanitizePoolOrder) both on save and again in Controller.connectAsync,
	// so a hand-edited config file cannot put an unsafe transport in the pool
	// either. See connection.go's allowedPoolTransports for why each member
	// qualifies — they qualify by two different mechanisms, one of which
	// (ForceRelay) this client did not previously set at all.
	TransportPool []string `json:"transportPool"`

	// Relay chaining (ADR-0038, issue #93 here; issue #28 wired the walk
	// client first and is the reference for all three). How many nodes a
	// RELAYED path is routed through, so no single relay links the user to
	// their exit — the privacy property the transport was built for, and
	// unreachable from this client until #93.
	//
	//   - RelayHops mirrors core.Config.RelayHops. 0 or 1 (the default) is
	//     today's single relay and needs neither field below. 2+ builds a
	//     chain and REQUIRES both: chaining is fail-closed, so a chain that
	//     cannot be built fails the connect rather than silently falling back
	//     to fewer hops (core/relaychain.go's file doc). That failure reaches
	//     the user as its own sentence rather than a generic connection
	//     error — see state.go's relayChainFailedPrefix.
	//   - RelayDirectoryPath is a file path to a coordinator-signed snapshot,
	//     read fresh at every connect and re-read by the engine thereafter
	//     (issue #27). Mirrors cmd/node's -relay-directory.
	//   - RelayDirectoryKey is that snapshot's signing key, hex — mirroring
	//     AdmissionPubKey's hex-string shape rather than core.Config's own
	//     RelayDirectoryKey, which is raw ed25519.PublicKey bytes.
	//     LoadRelayDirectory decodes this before it reaches core.Config.
	RelayHops          int    `json:"relayHops"`
	RelayDirectoryPath string `json:"relayDirectoryPath"`
	RelayDirectoryKey  string `json:"relayDirectoryKey"`

	// Volunteering this connection back to the network (issue #12) — the
	// desktop half of the switch cmd/node got in 8cf741a, and the only field
	// group here that makes this client SERVE rather than consume. See
	// volunteer.go for the ruling these four implement and for every check
	// they are put through; this comment is only what they are.
	//
	// VolunteerRelay and VolunteerExit are two independent opt-ins, both
	// false by default, and there is deliberately no single field spanning
	// them. That is the ruling, not an implementation detail: a relay carries
	// other people's traffic encrypted and blind-forwarded, so it costs
	// bandwidth, while an exit egresses their traffic under this machine's own
	// IP and jurisdiction, which is legal exposure. One field covering both
	// would let somebody who meant to donate bandwidth accept liability they
	// never read about. Two booleans make the bundle unsayable rather than
	// merely avoidable.
	//
	// VolunteerAdvertise and VolunteerExitKey are what the EXIT half cannot
	// work without, and they carry the Volunteer prefix because that is the
	// only reason they exist here: unlike Bypass/DNS/TransportPool above, they
	// mirror no field this client already had, they are inert unless
	// VolunteerExit is set, and grouping them under the opt-in that requires
	// them is what makes that dependency legible in a config file somebody is
	// hand-editing.
	//
	//   - VolunteerAdvertise is the host:port a relay dials to reach this
	//     exit, mapping to core.Config.Advertise, which core.New REFUSES to
	//     default (engine.go: "exit role requires Advertise host:port"). It
	//     has to be the address the internet reaches this machine at, with
	//     that port forwarded here. core.Config.ListenAddr is DERIVED from its
	//     port rather than configured separately — see VolunteerPlan.
	//   - VolunteerExitKey is a persistent X25519 private key, 64 hex chars,
	//     mapping to core.Config.ExitKeyHex. An exit's node id IS its public
	//     key, so a key generated afresh at every start is a new identity at
	//     every start while the signed directory clients cache still names the
	//     old one. Stored in this file, which SaveConfig writes 0600, on the
	//     same footing as TURNPass above; NewExitKeyHex generates one so no
	//     desktop user is sent to a command line for it.
	//
	// Nothing here is required by the RELAY opt-in, which is the ruling again
	// on the configuration side: demanding an exit's setup of somebody who
	// explicitly declined the exit would put the exit's cost back on them.
	VolunteerRelay     bool   `json:"volunteerRelay"`
	VolunteerExit      bool   `json:"volunteerExit"`
	VolunteerAdvertise string `json:"volunteerAdvertise"`
	VolunteerExitKey   string `json:"volunteerExitKey"`

	// The account service (bacchus#163, ADR-0056). This is the first group of
	// fields in this file that makes the client talk to anything other than the
	// coordinator pool, and every one of them is OPTIONAL: a deployment that runs
	// no account service leaves all five empty and is not degraded by doing so,
	// exactly as it leaves AdmissionPubKey empty today. That is not politeness —
	// core's device-credential gate is off unless a coordinator enables it, and a
	// Bacchus network without an entitlement authority is a supported shape.
	//
	// AccountServiceURLs, AccountServiceAudience and AccountServiceCA are the
	// three values an operator hands over together, and none of them can be
	// discovered:
	//
	//   - AccountServiceURLs are "https://host:port" each, scheme and host only.
	//     Plain http is refused: the assertions this client signs authenticate it
	//     TO the service and cover no response byte, so the credential travelling
	//     back is unprotected without TLS and an attacker who suppressed the
	//     request could simply complete it and keep the result.
	//   - AccountServiceAudience is the service's own identity, bound into every
	//     assertion. It is deliberately never in any response, so it MUST arrive
	//     out of band; a client that read it from the reply it was about to sign
	//     against would let the responder choose the binding.
	//   - AccountServiceCA is a PEM file authenticating the service's TLS
	//     identity. Required whenever a URL is set, and the system's public
	//     root pool is never consulted even as a fallback — the service is
	//     reached under a name chosen for camouflage, so a publicly-trusted
	//     certificate for that name authenticates the decoy rather than the
	//     service.
	//
	// # Why the address is a list (bacchus#192)
	//
	// The account service runs on anonymously rented infrastructure and its
	// address WILL change. A device renews as soon as it enters its renewal margin
	// and holds the rest as slack, so a service that becomes unreachable at T
	// takes the first devices offline at T + ~6 h — not the 42 hours between
	// renewals. Naming the successor address here BEFORE the move is what makes a
	// planned move survivable: the client rotates to it by itself, with nothing to
	// re-download and nobody to tell.
	//
	// Every address shares this one audience and this one pinned CA. There is
	// deliberately no per-address CA or audience to configure: that is what keeps
	// this a list of LOCATIONS rather than a list of trust roots, and an address
	// that does not present the pinned identity is unreachable rather than
	// trusted. accountclient.New enforces it for the whole list at once.
	//
	// On its own it does not help an UNPLANNED move — a list the client cannot
	// update goes stale together. What updates it is the signed directory
	// (bacchus#193, ADR-0061): with an Invite set, the "account" entries of a
	// verified snapshot REPLACE this list at connect time, and this is the seed
	// the client uses until it holds one. The two are not alternatives — the
	// audience and CA below are still what pin the identity of every address in
	// either list, and neither is discoverable.
	AccountServiceURLs []string `json:"accountServiceUrls"`

	// AccountServiceURL is the older single-address key, still read (bacchus#192,
	// wave ruling R5). It is on installed clients' disks today, so an upgrade must
	// not silently stop reaching the account service — which would cost that
	// device its access six hours later, at the far end of a change it never saw.
	//
	// AccountServiceAddresses resolves the two: the list wins when it has
	// anything in it, and this is used when it does not. Nothing rewrites the
	// user's file to migrate between them — a load that quietly rewrote what it
	// read would take a downgrade away from anyone who tried this build — so both
	// keys survive a Settings save exactly as they were found. omitempty keeps a
	// client that never had this key from acquiring an empty one and learning
	// about the deprecated spelling from its own config file.
	AccountServiceURL      string `json:"accountServiceUrl,omitempty"`
	AccountServiceAudience string `json:"accountServiceAudience"`
	AccountServiceCA       string `json:"accountServiceCa"`

	// DeviceCredDir is where this device's own keypair, its device credential and
	// its admission credential live across restarts — core.Config.DeviceCredDir,
	// which this client set nowhere at all before #163 and therefore held no
	// device credential under any configuration.
	//
	// Empty is NOT "off": DefaultDeviceCredDir picks a per-user directory beside
	// the config file, because the alternative core documents for an empty value
	// is a fresh device identity at every launch, and a device identity that
	// changes is an enrollment spent on a device that no longer exists. An
	// operator who genuinely wants the in-memory behaviour has core's own field
	// for it and is not configuring a desktop client.
	DeviceCredDir string `json:"deviceCredDir"`

	// ClaimCode is a ONE-SHOT bootstrap value: the code an operator hands a user
	// so that this device can enroll. It is redeemed at the next connect and
	// ERASED FROM THIS FILE the moment enrollment succeeds.
	//
	// It is here, rather than in a dialog, because there is no settings surface
	// for it yet and this file is the client's existing operator-facing seam —
	// see ADR-0056 §3, which rules that the field is the interim and the dialog
	// is the shape. What is NOT interim is the erasure: a claim code is a bearer
	// secret that is spent exactly once, the account service erases its own copy
	// on redemption rather than flagging it, and a client that kept a spent one
	// on disk would be the only remaining record that the code ever existed.
	//
	// A code that is REFUSED is left in place, deliberately. A user who mistyped
	// needs to see and correct what they typed, and erasing it would leave them
	// with an empty field and no idea what to put back.
	ClaimCode string `json:"claimCode"`

	// DeviceLabel is what the account's owner sees this device called in their
	// own device list. It travels to the account service in the clear and is
	// stored there durably.
	//
	// This client NEVER derives it from the machine. A hostname is a username on
	// most desktops and a real name on many, and the transport specification
	// singles this field out as "the one field in this system a user might put a
	// name in" precisely because it is the one place identifying text can enter
	// by accident. Empty uses DefaultDeviceLabel, which says nothing about
	// anybody.
	DeviceLabel string `json:"deviceLabel"`

	// Update is the signed release channel (issue #34, ADR-0052, ADR-0065). One
	// nested object rather than four more flat keys, because it is a feature most
	// users never configure and the flat key space above is already long.
	//
	// The zero value is updates OFF, which is right for a client installed by hand
	// from a downloaded artifact and never told where releases live. See
	// UpdateConfig in update.go for what each field means and for the two rules the
	// whole path is made of: the client never polls, and it fetches only through its
	// own tunnel.
	Update UpdateConfig `json:"update"`
}

// DefaultDeviceLabel is the device label used when Config.DeviceLabel is empty:
// a word, not a machine's name. Every device on every account sharing it is the
// intended outcome — a label that distinguishes devices is a label a user chose
// to make distinguishing, and one derived here would distinguish them to the
// service whether or not they meant it to.
const DefaultDeviceLabel = "desktop"

// DefaultDeviceCredDir is where this client keeps its device identity when
// Config.DeviceCredDir is empty: a "device" directory beside the per-user config
// file, which is the one location this client already knows it can write to and
// already keeps 0600 secrets in.
//
// Deliberately NOT next to the executable, even though LoadConfig will read a
// config from there. The exe-adjacent path is a portable install, and issue
// #118's finding applies with more force to this directory than it did to the
// config file: a device key written next to a binary in /usr/local/bin fails on
// permissions for the ordinary user, and the failure mode core documents for an
// unwritable key path is a hard construction error at connect.
//
// Returns "" when the OS cannot name a per-user config directory, which
// Controller reads as "no device credential on this machine" rather than
// guessing.
func DefaultDeviceCredDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "Bacchus", "device")
}

// DefaultDirectoryCachePath is where this client keeps the last signed
// cold-start snapshot it verified (bacchus#193): one file beside the per-user
// config, on the same reasoning DefaultDeviceCredDir gives for not writing next
// to the executable.
//
// Not user-configurable, mirroring DefaultSelectionDir: a cache of something the
// network hands out is an implementation detail, and the value of a knob here
// would be to point two installs at one file — which is the one thing that must
// not happen, since a snapshot is verified against the invite that fetched it.
//
// The bytes are the SIGNED wire form, saved verbatim, so they carry no secret
// (coldstart.Snapshot's own doc) and are worthless to anyone who does not also
// hold the signing key to check them against. The file is written by
// coldstart.SaveCache, which is atomic — a torn cache would fail Verify and send
// the next launch to the network, which for the users this exists for is exactly
// what may be unreachable at that moment.
//
// Returns "" when the OS cannot name a per-user config directory, which
// AcquireDirectory reads as "do not cache" rather than guessing at a path.
func DefaultDirectoryCachePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "Bacchus", "directory.snapshot")
}

// AccountServiceConfigured reports whether this config names an account service
// at all. False is a complete, supported deployment: no enrollment, no renewal,
// and whatever core/devicestore already holds is what this device presents.
func (c Config) AccountServiceConfigured() bool {
	return len(c.AccountServiceAddresses()) > 0
}

// AccountServiceAddresses is every address this config names for the account
// service, in preference order, trimmed and with blanks dropped.
//
// The list key wins whenever it holds anything; the older single-address key is
// what is used when it does not (bacchus#192). The two are resolved here, at the
// point of use, and never by rewriting the Config — see AccountServiceURL on why
// a load that migrated the file would be worse than the duplication.
//
// A config that sets BOTH uses the list and ignores the single value. That is
// the only ordering that lets an operator replace a stale address without
// deleting a key: the alternative — folding the older value in — would resurrect
// exactly the address they were moving away from, at the front, since it is the
// one the client already believed in.
func (c Config) AccountServiceAddresses() []string {
	out := make([]string, 0, len(c.AccountServiceURLs))
	for _, u := range c.AccountServiceURLs {
		if s := strings.TrimSpace(u); s != "" {
			out = append(out, s)
		}
	}
	if len(out) > 0 {
		return out
	}
	if s := strings.TrimSpace(c.AccountServiceURL); s != "" {
		return []string{s}
	}
	return nil
}

// EffectiveDeviceCredDir is DeviceCredDir, or the default when it is empty.
func (c Config) EffectiveDeviceCredDir() string {
	if d := strings.TrimSpace(c.DeviceCredDir); d != "" {
		return d
	}
	return DefaultDeviceCredDir()
}

// EffectiveDeviceLabel is DeviceLabel, or DefaultDeviceLabel when it is empty.
func (c Config) EffectiveDeviceLabel() string {
	if l := strings.TrimSpace(c.DeviceLabel); l != "" {
		return l
	}
	return DefaultDeviceLabel
}

// BypassModeInclude and BypassModeExclude are the two values BypassMode
// accepts, matching clients/internal/enforcement/splittunnel.go's splitTunnelMode exactly
// (kept as plain strings here, not a typed enum, since Config.BypassMode -
// like every other Config field - round-trips through JSON as one).
const (
	BypassModeInclude = "include"
	BypassModeExclude = "exclude"
)

// DefaultDNSUpstream is used when Config.DNS is empty, and is the same value
// the Windows tray client defaulted to — one number, one sentence of
// documentation, both clients. Queried over DNS-over-TCP through the tunnel,
// never in the clear (see enforcement/killswitch_windows.go on why there is
// no plaintext-DNS allowance in the lockdown either).
const DefaultDNSUpstream = "1.1.1.1:53"

// NormalizeBypassMode mirrors clients/internal/enforcement/splittunnel.go's
// parseSplitTunnelMode: only "include" (case-insensitive, whitespace
// tolerant) means include-mode; anything else - "exclude", empty, unset,
// a typo - means exclude-mode, matching a fresh Config's zero value. Settings
// logic lives here rather than in settings.go (which cannot be unit-tested
// without a cgo/GUI toolchain) per ADR-0039's Fyne-free/Fyne-touching split.
func NormalizeBypassMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), BypassModeInclude) {
		return BypassModeInclude
	}
	return BypassModeExclude
}

// SplitBypassLines turns settings.go's multi-line bypass entry into a clean
// []string: one trimmed entry per non-blank line. This is the Settings
// window's equivalent of bacchus-fyne.config.example.json's Bypass array -
// typing a JSON array by hand is exactly the friction a settings window
// exists to remove.
func SplitBypassLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// JoinBypassLines is SplitBypassLines' inverse, for seeding the multi-line
// entry from a saved Config - one bypass entry per line.
func JoinBypassLines(bypass []string) string {
	return strings.Join(bypass, "\n")
}

// configCandidates returns the two places this client's config can live, each
// empty when the OS cannot answer for it: exePath is next to the executable,
// userPath is under this OS's per-user config directory.
//
// They are returned separately rather than as one list because LOADING and
// SAVING rank them differently - see configPaths and DefaultConfigPath.
func configCandidates() (exePath, userPath string) {
	if exe, err := os.Executable(); err == nil {
		exePath = filepath.Join(filepath.Dir(exe), "bacchus-fyne.config.json")
	}
	if dir, err := os.UserConfigDir(); err == nil {
		userPath = filepath.Join(dir, "Bacchus", "fyne-client.json")
	}
	return exePath, userPath
}

// configPaths is the LOAD order, most-specific first: next to the executable,
// then this OS's per-user config directory. A relative, portable install (a
// laptop with the exe on a USB stick, say) wants the former; a normal
// per-machine install wants the latter.
//
// This is deliberately NOT the order a save picks from. Which file to read is
// "whose config is most specific to this copy of the program", and an
// exe-adjacent file is a deliberate act that should win. Where to WRITE a
// first config is a different question with a different answer - see
// DefaultConfigPath.
func configPaths() []string {
	var p []string
	exePath, userPath := configCandidates()
	if exePath != "" {
		p = append(p, exePath)
	}
	if userPath != "" {
		p = append(p, userPath)
	}
	return p
}

// LoadConfig reads the first config file that exists, returning the path it
// was read from alongside it. Returns os.ErrNotExist (wrapped) and an empty
// path if none is present - a fresh install with no config yet, not an error
// the app should alarm about.
func LoadConfig() (Config, string, error) {
	var lastErr error = os.ErrNotExist
	for _, p := range configPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			lastErr = err
			continue
		}
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return Config{}, p, err
		}
		return c, p, nil
	}
	return Config{}, "", lastErr
}

// errNoConfigPath is SaveConfig's error for an empty path - a caller that
// never loaded a config and never asked DefaultConfigPath for one either.
var errNoConfigPath = errors.New("no config file path to save to")

// SaveConfig writes c back to path as indented JSON. Mirrors
// the retired Windows client's config.go's saveConfig (issue #75 there; issue #152 here,
// settings.go's save handler is the only caller): path is normally whatever
// LoadConfig reported reading from, so a Settings save lands back in the same
// file the user is already using, and DefaultConfigPath covers the
// fresh-install case where nothing was loaded yet.
//
// The parent directory is created if it is missing, and that is not a
// convenience: the per-user candidate is `<config dir>/Bacchus/fyne-client.json`,
// and nothing creates that `Bacchus` directory on a machine where this client
// has never saved. os.WriteFile does not create parents, so without this the
// very first save on a fresh install fails with "no such file or directory" -
// which is issue #118's failure again wearing a different errno. 0700 because
// the file underneath is 0600 and holds TURNPass and VolunteerExitKey; a
// world-readable directory around a 0600 secret is a smaller leak than the
// file itself but still a leak of what is installed and when it was last
// changed.
//
// # The write is atomic (bacchus#190)
//
// The file is staged whole beside itself, flushed, and renamed over the target,
// so the live config is never open for writing and there is no instant at which
// it holds a partial one. It used to end in os.WriteFile, which opens the live
// file with O_TRUNC and refills it: a process killed in that window left the
// user's whole configuration empty or short rather than losing one field, and the
// next launch read what the killed one left.
//
// That window is reached by an ordinary gesture rather than a rare
// administrative one. ClearClaimCode's caller is a CONNECT attempt, so this runs
// while the user is waiting on the network — and a client whose config came back
// empty mid-connect looks, to them, like the app lost their account at the exact
// moment they tried to use it. Nothing here is unreconstructible the way
// bacchus#178's bootstrap secrets are; the user retypes it. Being retypable is
// not a reason to lose it.
func SaveConfig(path string, c Config) error {
	if path == "" {
		return errNoConfigPath
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// Before the staging, not just before the write: the temporary file is
	// created in the target's OWN directory, so on a fresh install that directory
	// has to exist before there is anywhere to stage. This is issue #118's fix and
	// it must survive — the per-user candidate is <config dir>/Bacchus/, which
	// nothing else creates.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeConfigAtomic(path, b)
}

// writeConfigAtomic installs b at path by staging a complete file under
// ".<name>.tmp*" in path's own directory, flushing it, and renaming it over the
// target.
//
// Two mechanics are load-bearing rather than tidy, and they are the same two
// core/coldstart/atomic.go names:
//
//   - The staged file is created IN THE TARGET'S DIRECTORY. os.Rename is atomic
//     only within one filesystem, and a rename across one degrades to
//     copy-then-delete — exactly the half-written file this exists to prevent.
//   - The bytes are flushed BEFORE the rename, so a rename that becomes visible
//     ahead of the data it points at cannot leave the next launch reading an
//     empty config.
//
// Three consequences of replacing the file rather than rewriting it, each a real
// change from os.WriteFile: the result is mode 0600 every time rather than only
// at creation, which only ever narrows and this file holds turnPass and
// volunteerExitKey; a path that is a SYMLINK is replaced rather than written
// through; and a writer killed mid-save leaves its staged file behind, named so
// it sorts beside the config, is hidden from a plain ls, and can never be
// mistaken for the config itself.
//
// It does not fsync the directory, which is where every atomic writer in this
// repository stops: that is a question about whether the RENAME is durable, not
// whether the bytes are whole, and its failure mode restores a complete older
// file rather than a torn one.
//
// # On Windows the replacement can be refused
//
// Windows will not rename over a file another process holds open, so a save
// while something else — a text editor left open on the config — has it can
// return "the process cannot access the file". That is a legible failure that
// changes nothing on disk, and it is not a regression: os.WriteFile needed write
// access to the same handle and was refused by the same rule, having already
// been given the chance to truncate. The one thing that must not happen on that
// path is a config that is neither the old one nor the new one, and replacing
// the file is what rules it out on every platform.
//
// It is package-local, as coldstart's is, and for the reason coldstart's doc
// gives: consolidating the copies means editing correct, separately tested code
// in packages this did not own. bacchus#188 holds that question, and its own body
// asks for a wave in which those packages are not in flight.
func writeConfigAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	staged := tmp.Name()
	// Removed on every path that does not rename it away, so a failure leaves the
	// live config untouched AND nothing beside it for the user to wonder about. A
	// no-op once the rename has succeeded.
	defer func() { _ = os.Remove(staged) }()
	if err := writeStagedConfig(tmp, b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(staged, path)
}

// writeStagedConfig fills the staged file and flushes it, so everything that can
// fail has failed before anything is renamed over the file the next launch reads.
func writeStagedConfig(f *os.File, b []byte) error {
	// 0600 explicitly rather than whatever os.CreateTemp's mode survived the
	// umask: this replaces a file SaveConfig has always written 0600, and its
	// contents are the reason (see the doc above).
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

// ClearClaimCode erases Config.ClaimCode from whichever config file is actually
// in use, leaving every other field as it stands on disk.
//
// It re-reads before it writes rather than saving a Config the caller is
// holding, and that is the whole reason it exists as its own function. The
// caller here is a connect attempt that took its copy of the config when the
// user pressed Connect; the settings window may have written the file since. A
// blind save of the connect's copy would silently revert whatever was changed in
// between, which is a worse bug than the one this is fixing — so this reads what
// is there now, clears one field, and puts it back.
//
// The read-modify-write is safe against a torn WRITE (SaveConfig stages and
// renames, bacchus#190) and is deliberately not serialised against another
// writer: atomicity is a promise to a reader, and two savers racing is a
// last-writer-wins question this client does not have — the settings window and a
// connect are one process and one user.
//
// A missing config file is not an error: nothing is on disk to hold a spent
// claim code, which is the state this function exists to reach.
func ClearClaimCode() error {
	c, path, err := LoadConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if c.ClaimCode == "" {
		return nil
	}
	c.ClaimCode = ""
	return SaveConfig(path, c)
}

// DefaultConfigPath is the SAVE target: where SaveConfig should write when
// LoadConfig found no existing file (its path return was ""). It prefers the
// per-user config directory, which is the reverse of configPaths' load order,
// and the reversal is the fix for issue #118.
//
// It used to be configPaths()[0] - next to the executable. That was harmless
// only while every user ran the binary out of a build directory they owned.
// Issue #18's installer puts the GUI at /usr/local/bin, so the first thing a
// fresh user does in Settings tried to write /usr/local/bin/bacchus-fyne.config.json
// and failed on permissions. deploy/install.sh works around it by seeding the
// per-user file, which masks the bug for anyone who installed that way and
// leaves it live for anyone who did not - a downloaded binary, or a build
// installed into a system path by hand.
//
// Preference, in order:
//
//   - An exe-adjacent config that ALREADY EXISTS. That is a portable install
//     in use, and configPaths ranks it first, so saving anywhere else would
//     write a second file that load then permanently shadows - the user's
//     edits would appear to save and never take effect. Settings normally
//     passes the path LoadConfig reported and never reaches here in that case;
//     this keeps the guarantee inside the package that owns the ordering
//     rather than resting it on one caller in another file.
//   - The per-user config directory. Per-user settings belong in the user's
//     own directory, which they own by construction.
//   - Next to the executable, only when the OS cannot name a per-user config
//     directory at all.
//
// Deliberately NOT a writability probe, which is the other obvious fix. "Can I
// write here" is the wrong question: run this client under sudo and
// /usr/local/bin becomes writable, so a probe would put the config there, and
// the same user's next ordinary launch could read it but never save it again.
// Ownership answers the question correctly without depending on how the
// process happens to be privileged.
//
// Returns "" when neither candidate can be named - SaveConfig rejects an empty
// path with errNoConfigPath, so that surfaces as a save error on the Settings
// status line. The old form indexed configPaths()[0] unconditionally and
// panicked on that same case, taking the GUI down with it.
func DefaultConfigPath() string {
	exePath, userPath := configCandidates()
	if exePath != "" {
		if _, err := os.Stat(exePath); err == nil {
			return exePath
		}
	}
	if userPath != "" {
		return userPath
	}
	return exePath
}
