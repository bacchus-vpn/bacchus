// Connection-strategy settings: the transport ladder, relay chaining, and exit
// admission — the half of issue #93's configuration parity that is pure logic
// rather than widgets.
//
// It lives here rather than in settings.go for the reason NormalizeBypassMode
// and SplitBypassLines already live in config.go: ADR-0039's Fyne-free /
// Fyne-touching split makes this package the part a unit test can reach with no
// cgo/GUI toolchain at all, and clients/fyne itself has no test files. Every
// decision a wrong answer to which produces a broken config is therefore made
// here, and settings.go is left as wiring over it.
//
// Each function mirrors a same-named unexported one in
// the retired Windows client's settings.go, which #93 names as the reference for what every
// control is and what it validates. They are duplicated rather than shared
// because that file is package main behind a `windows` build tag and so is
// importable from nowhere — the same constraint clients/internal/enforcement's
// Policy doc records for the three independent definitions of the bypass-mode
// strings. Duplicated logic two clients must agree on is a real cost; it is
// paid in the one direction that keeps the mirrored behaviour ASSERTED (see
// connection_test.go) rather than assumed to have been copied correctly.
package appstate

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bacchus-vpn/bacchus/core"
)

// allowedPoolTransports is the set safe to actually enable for this client's
// pool; knownPoolTransports is every transport the ladder UI displays, in its
// default order. Two lists rather than one for the reason
// the retired Windows client's settings.go gives: a future transport can appear in the UI
// before it is proven tunnel-safe to enable.
//
// Both entries qualify today, but by two different routes, and the difference
// matters because only one of them was already wired here. A full-device
// tunnel can only carry a transport whose underlay address it can exclude from
// its own default route before the pool dials it:
//
//   - reality's exit address is learned at Dial time, so it is excluded late,
//     on the dial path, through core.Config.OnUnderlayDial. Controller has
//     wired that to the Enforcer since bacchus#59 (see underlayDialHook).
//   - webrtc's is fixed instead, by core.Config.ForceRelay pinning every
//     candidate to the configured TURN server — an address enforcement.Policy
//     already excludes. Controller did NOT set ForceRelay before #93; see
//     connectAsync, which now does, and says why the gate is `enf != nil`.
//
// Unexported, and reachable only through the functions below, so neither list
// can be mutated by a caller holding a package-level slice header.
var (
	allowedPoolTransports = []string{core.TransportWebRTC, core.TransportReality}
	knownPoolTransports   = []string{core.TransportWebRTC, core.TransportReality}
)

// ErrRelayChainConfig is ValidateRelayChainConfig's error for a hop count that
// asks for a chain with no directory to build one from. Exported so settings.go
// can recognise it, and because its text doubles as a translation key (see
// translations/settings.ru.json).
var ErrRelayChainConfig = errors.New("2 or more relay hops needs both the relay directory file and its public key")

// ErrAdmissionConfig is ValidateAdmissionConfig's error for a
// CRL-path-without-pubkey pair.
var ErrAdmissionConfig = errors.New("revocation list path requires the admission public key")

// NormalizeRelayHops clamps a saved or displayed hop count into
// [1, core.RelayHopsMax]. 0 — a fresh Config's zero value, or a settings file
// written before this client had the control — reads as "unset", which is
// today's single relay: the same 0/1-both-mean-1 normalization
// core/relaychain.go's chainDepth applies server-side, kept in sync here so the
// control never displays a value core would silently reinterpret.
//
// Above the ceiling is clamped only for DISPLAY. A value that high can only
// reach this client by hand-editing the config file, since the control itself
// offers nothing above core.RelayHopsMax; core.New's own construction-time
// refusal is still what enforces the ceiling for real, exactly as it does for
// every other path to Config.RelayHops. Mirrors normalizeRelayHops in
// the retired Windows client's settings.go.
func NormalizeRelayHops(hops int) int {
	if hops < 1 {
		return 1
	}
	if hops > core.RelayHopsMax {
		return core.RelayHopsMax
	}
	return hops
}

// RelayHopChoices is the ordered list of hop counts the settings control offers,
// "1" through core.RelayHopsMax as decimal strings. Derived from the ceiling
// rather than written out, so raising core.RelayHopsMax widens the control
// without a second edit here — and so the control cannot offer a depth core
// would refuse at construction, which is what the walk client's NumberEdit
// MaxValue does for it.
func RelayHopChoices() []string {
	out := make([]string, 0, core.RelayHopsMax)
	for i := 1; i <= core.RelayHopsMax; i++ {
		out = append(out, strconv.Itoa(i))
	}
	return out
}

// ParseRelayHops turns a RelayHopChoices entry back into a hop count, clamped
// through NormalizeRelayHops. Anything unparseable — an empty Select, a
// hand-edited value — normalizes to 1 rather than erroring: this is the display
// layer's inverse, and the only values it can legitimately receive are the ones
// RelayHopChoices produced.
func ParseRelayHops(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 1
	}
	return NormalizeRelayHops(n)
}

// ValidateRelayChainConfig reports whether hops/dirPath/dirKey describe a
// relay-chaining config core would accept at construction: chaining (hops >= 2,
// ADR-0038) is meaningless without a directory to select hops from and a key to
// verify it — core.Config.RelayDirectory/RelayDirectoryKey, both required
// together once hops asks for a chain. 1 hop, or unset, never needs a directory,
// matching core/relaychain.go's chainDepth normalization exactly.
//
// Catching the combination here turns a connect-time construction failure into
// a message in the dialog, before Save ever lets it out. Trims both string
// inputs first and returns the trimmed values, so the caller persists what was
// actually validated rather than the raw widget text — otherwise a whitespace-
// only key paired with a real path passes this check and fails later inside
// core instead. Mirrors validateRelayChainConfig in the retired Windows client's settings.go.
func ValidateRelayChainConfig(hops int, dirPath, dirKey string) (trimmedPath, trimmedKey string, err error) {
	dirPath = strings.TrimSpace(dirPath)
	dirKey = strings.TrimSpace(dirKey)
	if hops >= 2 && (dirPath == "" || dirKey == "") {
		return "", "", ErrRelayChainConfig
	}
	return dirPath, dirKey, nil
}

// ValidateAdmissionConfig reports whether pubKey/crlPath describe an admission
// config core would accept at construction: crlPath is meaningless (and
// rejected by core/exit_admission.go's buildExitVerifier) without pubKey also
// set. Both blank (admission off) and pubKey alone (verify, but skip
// revocation) are valid.
//
// Trims first, mirroring core's own buildExitVerifier: without that, a
// whitespace-only pubkey paired with a real crlPath passes this check and only
// core's trim-then-reject turns it into a raw "requires AdmissionPubKey" error
// from a field the user never got a chance to fix. Mirrors
// validateAdmissionConfig in the retired Windows client's settings.go.
func ValidateAdmissionConfig(pubKey, crlPath string) (trimmedPubKey, trimmedCRLPath string, err error) {
	pubKey = strings.TrimSpace(pubKey)
	crlPath = strings.TrimSpace(crlPath)
	if crlPath != "" && pubKey == "" {
		return "", "", ErrAdmissionConfig
	}
	return pubKey, crlPath, nil
}

// SanitizePoolOrder filters order down to allowedPoolTransports, preserving
// order's relative sequence and dropping duplicates and unknown entries.
// Applied both when the settings window saves the ladder and again in
// Controller.connectAsync before core.Config is built, so a hand-edited config
// file cannot smuggle an unsafe transport into the pool either. Mirrors
// sanitizePoolOrder in the retired Windows client's settings.go.
func SanitizePoolOrder(order []string) []string {
	allowed := map[string]bool{}
	for _, t := range allowedPoolTransports {
		allowed[t] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(order))
	for _, t := range order {
		if !allowed[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// LadderDisplayOrder returns saved (the persisted, already-sanitized pool)
// followed by any knownPoolTransports entries it is missing, so a
// never-configured or partially-configured ladder still shows every transport
// the control knows about in a stable default order. Mirrors
// ladderDisplayOrder in the retired Windows client's settings.go.
func LadderDisplayOrder(saved []string) []string {
	out := append([]string(nil), saved...)
	have := map[string]bool{}
	for _, t := range out {
		have[t] = true
	}
	for _, t := range knownPoolTransports {
		if !have[t] {
			out = append(out, t)
		}
	}
	return out
}

// MoveLadderItem returns a copy of order with the element at idx swapped with
// its neighbour in direction dir (-1 up, +1 down). An idx out of range, or a
// move that would run off either end, returns order unchanged: reordering a
// ladder is always a swap with an adjacent element, never a wrap-around or a
// clamp-and-move-to-the-end, so repeated clicks at an edge are inert rather
// than surprising. Mirrors moveLadderItem in the retired Windows client's settings.go.
func MoveLadderItem(order []string, idx, dir int) []string {
	out := append([]string(nil), order...)
	j := idx + dir
	if idx < 0 || idx >= len(out) || j < 0 || j >= len(out) {
		return out
	}
	out[idx], out[j] = out[j], out[idx]
	return out
}

// LoadRelayDirectory reads and decodes the signed-snapshot pair a chained
// connect needs, returning (nil, nil, nil) when no chain was asked for — hops
// of 0 or 1 is today's single relay and needs neither field, so nothing is read
// from disk for the overwhelmingly common case.
//
// Called from Controller.connectAsync before core.New, mirroring the same load
// in the Windows tray client's connect() and cmd/node's own -relay-directory handling,
// and for the same reason: a missing file or a non-hex key fails here, named,
// rather than surfacing later as core's "relay chaining needs a signed relay
// directory" from a field the user cannot tell was the cause. The directory is
// read fresh at every connect; core keeps it fresh thereafter from
// RelayDirectoryPath (issue #27).
func LoadRelayDirectory(hops int, dirPath, dirKey string) ([]byte, ed25519.PublicKey, error) {
	if hops < 2 {
		return nil, nil, nil
	}
	b, err := os.ReadFile(dirPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read relay directory: %w", err)
	}
	k, err := hex.DecodeString(strings.TrimSpace(dirKey))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("relay directory public key must be %d bytes of hex", ed25519.PublicKeySize)
	}
	return b, ed25519.PublicKey(k), nil
}

// DefaultSelectionDir is where the pool persists what it learned — the winning
// (transport, exit, mode) per network and geo (core.Config.SelectionDir). Not
// user-configurable, mirroring the walk client's defaultSelectionDir: #93 asks
// for the pool to be usable, not for every implementation detail to become a
// knob. Sits beside the per-user config file (configPaths' second candidate)
// rather than next to the executable, since a portable install's directory may
// not be writable.
//
// Returns "" if this OS reports no user config directory at all, which core
// reads as "learn in memory only, forget on exit" — a degraded pool rather than
// a failed connect, which is the right trade for a cache.
func DefaultSelectionDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "Bacchus", "selection")
}
