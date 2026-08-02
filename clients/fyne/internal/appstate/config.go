// Runtime configuration. No endpoints are compiled into the binary - they load
// from a JSON file next to the executable, or the per-user config directory
// (mirrors clients/windows/config.go's precedence; see that file's doc comment
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

	// AdmissionPubKey and AdmissionCRLPath mirror the same-named core.Config
	// fields, and mirror what clients/windows already passes (its main.go sets
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

	// Bypass, BypassMode, DisableKillSwitch, and DNS mirror clients/windows's
	// same-named Config fields (config.go) exactly - same names, same JSON
	// keys, same semantics - and as of bacchus#59 they are live on any
	// platform with an Enforcer, which today means Windows: Controller passes
	// them straight into enforcement.Policy, and the same code that has
	// always honored them for clients/windows honors them here.
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

	// TransportPool mirrors core.Config.TransportPool and clients/windows's
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
}

// BypassModeInclude and BypassModeExclude are the two values BypassMode
// accepts, matching clients/windows/splittunnel.go's splitTunnelMode exactly
// (kept as plain strings here, not a typed enum, since Config.BypassMode -
// like every other Config field - round-trips through JSON as one).
const (
	BypassModeInclude = "include"
	BypassModeExclude = "exclude"
)

// DefaultDNSUpstream is used when Config.DNS is empty, and is the same value
// clients/windows defaults to (its config.go) — one number, one sentence of
// documentation, both clients. Queried over DNS-over-TCP through the tunnel,
// never in the clear (see enforcement/killswitch_windows.go on why there is
// no plaintext-DNS allowance in the lockdown either).
const DefaultDNSUpstream = "1.1.1.1:53"

// NormalizeBypassMode mirrors clients/windows/splittunnel.go's
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
// clients/windows/config.go's saveConfig (issue #75 there; issue #152 here,
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
func SaveConfig(path string, c Config) error {
	if path == "" {
		return errNoConfigPath
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
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
