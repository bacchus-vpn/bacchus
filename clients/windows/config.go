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
	// pre-#75 behavior exactly (a single transport into a coordinator-picked
	// country).
	//
	//   - Geo is the user's preferred country, persisted across restarts. It is
	//     the SEED for the tray picker, not a second, competing input: onReady
	//     copies it into the picker's selection before the first refresh, and
	//     from then on the picker is the single authority for which country a
	//     connect names (see currentCountryLabel in main.go). Saving a new Geo
	//     re-seeds the picker. There is deliberately only one country in play at
	//     a time — after country-only assignment (issue #146, ADR-0042) both this
	//     field and the picker feed the same core.Config.Geo, and two independent
	//     controls writing one field is how a setting ends up silently doing
	//     nothing.
	//   - TransportPool mirrors core.Config.TransportPool: a preference-ordered
	//     ladder. Empty turns the pool off. connect() additionally restricts
	//     whatever is saved here to allowedPoolTransports before it ever
	//     reaches core.Config — see settings.go's safety note.
	Geo           string   `json:"geo"`
	TransportPool []string `json:"transportPool"`

	// ExitID is a DEAD setting, kept only so that a config file written before
	// country-only assignment (issue #146, ADR-0042) can still be recognised and
	// called out. Nothing reads it into core.Config; connect() logs one line
	// saying the pin is ignored and moves on.
	//
	// Deleting the field would be worse than keeping it: encoding/json drops an
	// unknown "exitId" key without a word, so a user who pinned an exit would go
	// on believing their traffic leaves through that one node while the
	// coordinator has in fact been choosing for them. The whole point of the
	// field now is to make that impossible to miss. Remove it once no config
	// file in the wild plausibly still carries a pin.
	//
	// Deprecated: has no effect. Use Geo to choose a country.
	ExitID string `json:"exitId"`

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

	// Mesh-walk recovery (issue #31/#111/#115/#122/#129, ADR-0037) — opts
	// this client into mid-session self-healing when every coordinator
	// becomes unreachable, mirroring cmd/node's -mesh-peers/-mesh-proof/
	// -mesh-pubkey flags. All three are required together — core.Engine's
	// own meshRecoveryConfigured fails closed on a partial set — or all
	// three left blank (the default), which reproduces pre-#129 behavior:
	// watchMeshRecovery (main.go) is wired unconditionally but its
	// NeedsRecovery() channel never closes.
	//
	//   - MeshPeers mirrors core.Config.MeshPeers: courier addresses
	//     (host:port) of relay/exit nodes met in a prior session, running
	//     -courier-listen.
	//   - MeshProofPath mirrors cmd/node's -mesh-proof: a file path to a
	//     cached signed snapshot (cmd/coldstart-bootstrap -cache) presented
	//     to peers as proof of prior contact. A path, not an inline value,
	//     for the same reason AdmissionCRLPath is a path above: this is not
	//     a value worth pasting into a settings text box.
	//   - MeshPubKey mirrors core.Config.MeshPubKey: the coordinator's
	//     snapshot-signing public key, hex-encoded, verifying any snapshot
	//     recovered via mesh-walk.
	MeshPeers     []string `json:"meshPeers"`
	MeshProofPath string   `json:"meshProofPath"`
	MeshPubKey    string   `json:"meshPubKey"`
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
