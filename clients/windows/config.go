//go:build windows

// Runtime configuration for the Bacchus tray client. No endpoints or credentials
// are compiled into the binary — they load from bacchus.config.json (next to the
// exe) or %APPDATA%\Bacchus\config.json. Ship config.example.json as a template.
package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Config holds the network endpoints and TURN credentials the client needs.
type Config struct {
	// Coordinators is the rendezvous pool: one or more coordinator UDP
	// host:port endpoints (issue #6). The client rotates across them, so
	// signaling survives one member being blocked. A single-entry list is the
	// common case.
	Coordinators []string `json:"coordinators"`
	STUN         string   `json:"stun"` // stun:host:port
	TURN         string   `json:"turn"` // turn:host:port
	TURNUser     string   `json:"turnUser"`
	TURNPass     string   `json:"turnPass"`
	DNS          string   `json:"dns"` // upstream host:port queried (via the tunnel) for every intercepted DNS request; defaults to defaultDNSUpstream when empty

	// Bypass lists destinations — IPs, CIDRs, and/or domains — that split
	// tunnelling routes off the tunnel and out the physical interface instead
	// (e.g. RU banking/gov/streaming sites that reject a foreign exit IP).
	// What "off the tunnel" means for this list, and which direction its route
	// goes, is controlled by BypassMode. In "exclude" mode (the common case),
	// domains are resolved continuously as the DNS interceptor sees queries
	// for them (splittunnel.go), since a CDN-backed domain's IPs can change
	// mid-session, and the kill-switch allowlist stays in sync automatically
	// including with IPs learned after the tunnel is already up. "include"
	// mode gets the same connect-time resolution but not the continuous
	// mid-session tracking — see the client README's Split tunnelling section.
	Bypass []string `json:"bypass"`

	// BypassMode selects how Bypass is interpreted:
	//   - "exclude" (default, empty also means this): Bypass entries go direct;
	//     everything else is tunnelled. This is the common case (a short list
	//     of sites that must keep the user's real IP).
	//   - "include": Bypass entries are the *only* thing tunnelled; everything
	//     else goes direct. Useful for routing just a specific set of
	//     destinations through the exit while leaving normal browsing alone.
	//     Combining this with the kill-switch blocks (not leaks) that
	//     "everything else" traffic while connected — see the README.
	BypassMode string `json:"bypassMode"`

	// DisableKillSwitch turns the fail-closed kill-switch off. Default (false)
	// keeps it on — if the tunnel drops, traffic is blocked rather than
	// leaking. Only set this if you knowingly accept plaintext fallback.
	DisableKillSwitch bool `json:"disableKillSwitch"`

	// Connection-strategy settings (issue #75, ADR-0036): the client-side
	// surface over core's transport pool / per-user failover (ADR-0028), edited
	// via the "Connection settings" window (settings.go) and merged into
	// core.Config by connect(). All optional; the zero value reproduces
	// pre-#75 behavior exactly (single transport, tray-picked exit only).
	//
	//   - ExitID is a manual exit pin, now legacy: naming a specific exit was
	//     removed for everyone (issue #146, ADR-0042) — the coordinator picks
	//     the exit inside the country you choose from the tray. connect()
	//     logs and ignores a saved value rather than acting on it, and the
	//     Settings field that writes it is disabled for the same reason
	//     (issue #6).
	//   - TransportPool mirrors core.Config.TransportPool: a preference-ordered
	//     ladder. Empty turns the pool off. connect() additionally restricts
	//     whatever is saved here to allowedPoolTransports before it ever
	//     reaches core.Config — see settings.go's safety note.
	//
	// Deliberately no Geo field: the country you exit in is the tray picker's
	// job, and only its job (issue #6) — see currentCountryLabel and
	// connect()'s "the country the user picked is the whole of what a connect
	// names." A separate Settings-owned geo control existed briefly, wrote
	// this struct, and was read by nothing; removed rather than wired up, to
	// keep exactly one control deciding the country. See README.md's
	// "Connection settings" section for the precedence rule this settled on.
	ExitID        string   `json:"exitId"`
	TransportPool []string `json:"transportPool"`

	// Exit admission (issue #60/#69/#90, ADR-0026) — optional, end-to-end
	// verification of each exit's admission credential, independent of the
	// coordinator. Previously unwired on this client entirely (fail-open,
	// same as core.Config with neither field set); issue #116 adds these two
	// so a real end user can turn it on, and so any CRL configured hot-reloads
	// (Engine.reloadCRLLoop) instead of loading once at connect.
	//
	//   - AdmissionPubKey mirrors core.Config.AdmissionPubKey: the admission
	//     authority's ed25519 public key, hex-encoded. Empty (default) does not
	//     verify exits at all, matching this client's behavior before #116.
	//   - AdmissionCRLPath mirrors core.Config.AdmissionCRLPath: a file path to
	//     a signed revocation bundle (cmd/admission-issue -crl), re-read every
	//     few minutes by the engine. Meaningless without AdmissionPubKey also
	//     set. This client deliberately exposes only the path-based source —
	//     never core.Config.AdmissionCRL (inline, load-once) — mirroring
	//     cmd/node's own -admission-crl flag, which maps to the same field for
	//     the identical reason: a GUI client's CRL is naturally a file an
	//     operator drops on disk, not a value worth pasting into a text box
	//     every time it rotates.
	AdmissionPubKey  string `json:"admissionPubKey"`
	AdmissionCRLPath string `json:"admissionCrlPath"`

	// Relay chaining (issue #142, GUI issue #28) — how many nodes a RELAYED
	// path is routed through, so no single relay links you to your exit
	// (ADR-0038). Edited via the "Connection settings" window's "Relay hops"
	// group (settings.go).
	//
	//   - RelayHops mirrors core.Config.RelayHops: 0 or 1 (the default) is
	//     today's single relay and needs neither field below. 2+ builds a
	//     chain and REQUIRES both — connect() refuses to start rather than
	//     silently falling back to fewer hops (core/relaychain.go's file doc:
	//     chaining is fail-closed, never silently downgraded).
	//   - RelayDirectoryPath is a file path to a coordinator-signed snapshot
	//     (e.g. cmd/coldstart-bootstrap -cache), read fresh at every connect —
	//     mirroring cmd/node's -relay-directory. Verified against
	//     RelayDirectoryKey and must be unexpired.
	//   - RelayDirectoryKey is that snapshot's signing key, hex — the
	//     coordinator's, from cmd/coordinator -print-bootstrap-pubkey.
	//     Mirrors AdmissionPubKey's hex-string shape, not core.Config's own
	//     RelayDirectoryKey (which is raw ed25519.PublicKey bytes; connect()
	//     decodes this before handing it to core.Config).
	RelayHops          int    `json:"relayHops"`
	RelayDirectoryPath string `json:"relayDirectoryPath"`
	RelayDirectoryKey  string `json:"relayDirectoryKey"`
}

// defaultDNSUpstream is used when Config.DNS is empty. It's queried from the
// exit's network, over DNS-over-TCP through the SOCKS tunnel — never
// reachable directly from the client, so Cloudflare being blocked in Russia
// (see workspace notes) doesn't apply here.
const defaultDNSUpstream = "1.1.1.1:53"

// configPaths lists candidate config locations, most-specific first.
func configPaths() []string {
	var p []string
	if exe, err := os.Executable(); err == nil {
		p = append(p, filepath.Join(filepath.Dir(exe), "bacchus.config.json"))
	}
	if ad := os.Getenv("APPDATA"); ad != "" {
		p = append(p, filepath.Join(ad, "Bacchus", "config.json"))
	}
	return p
}

// loadConfig reads the first config file that exists. Returns os.ErrNotExist if
// none is present.
func loadConfig() (Config, string, error) {
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

// saveConfig writes c back to path as indented JSON (issue #75: the
// "Connection settings" window is the first in-app config editor this client
// has had — previously the file was hand-edited only). path is normally
// whatever loadConfig reports it read from, so an edit lands back in the same
// file the user is already using; when the client started with no config file
// at all (a fresh install), the caller falls back to configPaths()[0].
func saveConfig(path string, c Config) error {
	if path == "" {
		return errNoConfigPath
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

var errNoConfigPath = errors.New("no config file path to save to")
