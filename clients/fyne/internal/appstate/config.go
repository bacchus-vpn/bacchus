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

// Config holds this client's settings. Coordinators/STUN/TURN/admission are
// the connection endpoints (unchanged since the #148 skeleton, hand-edited in
// the config file - there is still no in-app editor for these). Bypass
// through LaunchOnBoot (issue #152) are the user-facing Settings window's
// fields, edited via settings.go and persisted the same way.
//
// The admission fields are not UI: they are a security check, and leaving
// them out did not make this client simpler, it made it fail open. See their
// doc.
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
	// keys, same semantics - but this client has no TUN device (ADR-0039's
	// Scope): no route table changes, no DNS interception, no OS-level
	// firewall lockdown. core.Config itself has no fields for any of these
	// three (confirmed by reading it - they are entirely clients/windows's
	// own TUN-side machinery, in tunnel.go/splittunnel.go/killswitch.go), so
	// there is nothing in this client for them to reach yet. They are saved
	// here anyway, deliberately: forward-compatible config surface for
	// whichever later card ports tun2socks to this client, matching
	// ADR-0039's Consequences section ("the next client cards ... build on
	// Controller"). settings.go's window says so plainly, so a user turning
	// "kill-switch" on here never believes it is armed - the one thing this
	// app must never get wrong (see ui.go's stateDescription doc on the same
	// point).
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
}

// BypassModeInclude and BypassModeExclude are the two values BypassMode
// accepts, matching clients/windows/splittunnel.go's splitTunnelMode exactly
// (kept as plain strings here, not a typed enum, since Config.BypassMode -
// like every other Config field - round-trips through JSON as one).
const (
	BypassModeInclude = "include"
	BypassModeExclude = "exclude"
)

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

// configPaths lists candidate config locations, most-specific first: next to
// the executable, then this OS's per-user config directory. A relative,
// portable install (a laptop with the exe on a USB stick, say) wants the
// former; a normal per-machine install wants the latter.
func configPaths() []string {
	var p []string
	if exe, err := os.Executable(); err == nil {
		p = append(p, filepath.Join(filepath.Dir(exe), "bacchus-fyne.config.json"))
	}
	if dir, err := os.UserConfigDir(); err == nil {
		p = append(p, filepath.Join(dir, "Bacchus", "fyne-client.json"))
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
func SaveConfig(path string, c Config) error {
	if path == "" {
		return errNoConfigPath
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// DefaultConfigPath is where SaveConfig should write when LoadConfig found no
// existing file (its path return was "") - the first, most specific
// candidate configPaths lists.
func DefaultConfigPath() string {
	return configPaths()[0]
}
