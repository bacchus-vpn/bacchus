package appstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSaveConfigRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bacchus-fyne.config.json")

	want := Config{
		Coordinators:      []string{"203.0.113.10:51820"}, // TEST-NET-3 (RFC 5737): never a real Bacchus endpoint
		STUN:              "stun:203.0.113.10:3478",
		AdmissionPubKey:   "ababababababababababababababababababababababababababababababab", // placeholder hex-shaped string; round-trip doesn't validate key material
		AdmissionCRLPath:  `C:\Bacchus\revocations.crl`,
		Bypass:            []string{"example.com", "10.0.0.0/8"},
		BypassMode:        "include",
		DisableKillSwitch: true,
		DNS:               "1.1.1.1:53",
		AutoConnect:       true,
		LaunchOnBoot:      true,
	}
	if err := SaveConfig(path, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	// LoadConfig itself only ever walks configPaths() (exe-relative /
	// per-user config dir), which a t.TempDir() path is never one of, so read
	// the saved file back directly the same way LoadConfig would.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var readBack Config
	if err := json.Unmarshal(b, &readBack); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(readBack, want) {
		t.Fatalf("SaveConfig then read back = %+v, want %+v", readBack, want)
	}
}

func TestSaveConfigNoPath(t *testing.T) {
	if err := SaveConfig("", Config{}); err == nil {
		t.Fatal(`SaveConfig("", ...) succeeded, want an error`)
	}
}

func TestSaveConfigOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bacchus-fyne.config.json")

	if err := SaveConfig(path, Config{DNS: "1.1.1.1:53"}); err != nil {
		t.Fatalf("SaveConfig (first write): %v", err)
	}
	if err := SaveConfig(path, Config{DNS: "9.9.9.9:53"}); err != nil {
		t.Fatalf("SaveConfig (second write): %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var readBack Config
	if err := json.Unmarshal(b, &readBack); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if readBack.DNS != "9.9.9.9:53" {
		t.Fatalf("after overwrite, DNS = %q, want %q", readBack.DNS, "9.9.9.9:53")
	}
}

// TestLoadConfigReturnsPath is the round-trip proof that LoadConfig's path
// return is real, not a placeholder: a Settings save (settings.go) must land
// back in the exact file the app read from, or an editor with a config in
// the per-user directory would silently get a second, divergent file created
// next to the executable instead of updating the one they're using.
//
// Sets both APPDATA and XDG_CONFIG_HOME so this passes under go test on
// either OS os.UserConfigDir actually reads from (Windows/Linux); the unused
// one on either platform is simply ignored. configPaths' other candidate
// (exe-relative) resolves to the compiled test binary's own directory, which
// never has a bacchus-fyne.config.json in it, so LoadConfig falls through to
// the per-user one this test controls - the common "no portable install"
// case.
func TestLoadConfigReturnsPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	perUserDir := filepath.Join(dir, "Bacchus")
	if err := os.MkdirAll(perUserDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	want := Config{DNS: "1.1.1.1:53"}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	perUserPath := filepath.Join(perUserDir, "fyne-client.json")
	if err := os.WriteFile(perUserPath, b, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, path, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if path != perUserPath {
		t.Fatalf("LoadConfig path = %q, want %q", path, perUserPath)
	}
	if got.DNS != want.DNS {
		t.Fatalf("LoadConfig config = %+v, want %+v", got, want)
	}
}

// writeExeAdjacentConfig puts a config file where configPaths' FIRST candidate
// looks - the directory holding the running binary, which under go test is the
// compiled test binary's own build directory. Removal is registered with the
// test, so the "the exe's directory never has a config in it" assumption the
// rest of this file rests on holds again the moment the caller finishes.
//
// Skips rather than fails when the binary's directory cannot be written,
// because that is a property of where the test binary was put, not of the code
// under test.
func writeExeAdjacentConfig(t *testing.T, c Config) string {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return writeExeAdjacentFile(t, b)
}

// writeExeAdjacentFile is writeExeAdjacentConfig over raw bytes, for a test
// that needs the file's exact JSON rather than whatever marshalling a Config
// produces - the release bundle's template is written by the packaging job and
// not by this package, so a test about it has to state the bytes.
func writeExeAdjacentFile(t *testing.T, b []byte) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	path := filepath.Join(filepath.Dir(exe), "bacchus-fyne.config.json")
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("%s already exists - refusing to overwrite it", path)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Skipf("cannot write beside the test binary: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })
	return path
}

// TestBundleLayoutTemplateIsUsableAsIs is the CLIENT half of bacchus#136's
// third ruling, and the finding is that there was nothing to build: the
// release bundle is to place bacchus-fyne.config.json beside bacchus-fyne.exe
// with the endpoint keys present and empty, and every rule that has to hold
// for that to be the file the user edits AND the file Settings then saves to
// was already in place. What was missing is a test, because the packaging job
// lives in another repository directory and can catch no change to the
// precedence rules here.
//
// Three things have to hold together, and only the first is obvious:
//
//   - LoadConfig READS it, which needs the exe-adjacent candidate to be ranked
//     first. It is (configPaths), and a portable install is why.
//   - Empty endpoint keys parse to an unconfigured Config rather than an
//     error, so the app opens normally and the Connect refusal - not a startup
//     error banner - is what tells the user what to do.
//   - DefaultConfigPath returns THAT file, so a Settings save lands in the
//     file the bundle shipped instead of creating a second one under
//     %APPDATA% that the load order would then permanently shadow. This is the
//     bacchus#118 constraint arriving from the other direction, and it is the
//     one a "simplify the two path orders into one" change would break.
func TestBundleLayoutTemplateIsUsableAsIs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	// The shape ruled for the bundle: every endpoint key present, all empty.
	// Same shape deploy/install.sh writes on Linux when the example template
	// is not beside it.
	template := []byte(`{
  "coordinators": [],
  "stun": "",
  "turn": "",
  "turnUser": "",
  "turnPass": ""
}
`)
	bundlePath := writeExeAdjacentFile(t, template)

	cfg, path, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig on the bundle's own template: %v - the app would open with a config error banner instead of a usable window", err)
	}
	if path != bundlePath {
		t.Fatalf("LoadConfig path = %q, want the bundle's %q", path, bundlePath)
	}
	if len(cfg.Coordinators) != 0 {
		t.Errorf("Coordinators = %v, want none - the template is the unconfigured state", cfg.Coordinators)
	}
	if got := DefaultConfigPath(); got != bundlePath {
		t.Fatalf("DefaultConfigPath = %q, want the bundle's %q - a Settings save would write a second file that the load order then shadows forever", got, bundlePath)
	}
}

// TestLoadConfigPrefersExeAdjacent pins the LOAD half of issue #118's split:
// with a config in BOTH candidate locations, the exe-adjacent one wins. That
// ordering is what makes a portable install (exe plus config on a USB stick)
// work, and issue #118 changed only the save target, so a later change that
// "simplifies" the two orders back into one must fail here.
func TestLoadConfigPrefersExeAdjacent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	perUserDir := filepath.Join(dir, "Bacchus")
	if err := os.MkdirAll(perUserDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	b, err := json.Marshal(Config{DNS: "9.9.9.9:53"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(perUserDir, "fyne-client.json"), b, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	exePath := writeExeAdjacentConfig(t, Config{DNS: "1.1.1.1:53"})

	got, path, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if path != exePath {
		t.Fatalf("LoadConfig path = %q, want the exe-adjacent %q", path, exePath)
	}
	if got.DNS != "1.1.1.1:53" {
		t.Fatalf("LoadConfig read the per-user file: DNS = %q, want %q", got.DNS, "1.1.1.1:53")
	}
}

// TestDefaultConfigPathPrefersPerUserDir is issue #118 itself. With the GUI
// installed at /usr/local/bin, the old DefaultConfigPath - configPaths()[0],
// next to the executable - sent a fresh user's first Settings save at a
// root-owned directory, and it failed on permissions. The save target is now
// the per-user config directory, which the user owns whatever the binary's
// directory happens to be.
func TestDefaultConfigPathPrefersPerUserDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	want := filepath.Join(dir, "Bacchus", "fyne-client.json")
	if got := DefaultConfigPath(); got != want {
		t.Fatalf("DefaultConfigPath = %q, want the per-user %q", got, want)
	}
}

// TestDefaultConfigPathKeepsExistingExeAdjacentConfig is the constraint the
// issue #118 fix had to respect: a user who ALREADY has a config next to the
// executable keeps saving to it. configPaths loads that file in preference to
// the per-user one, so defaulting a save to the per-user directory here would
// write a file that load then permanently shadows - every subsequent Settings
// save would appear to succeed and never take effect.
func TestDefaultConfigPathKeepsExistingExeAdjacentConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	exePath := writeExeAdjacentConfig(t, Config{DNS: "1.1.1.1:53"})

	if got := DefaultConfigPath(); got != exePath {
		t.Fatalf("DefaultConfigPath = %q, want the existing exe-adjacent %q", got, exePath)
	}
}

// TestSaveConfigCreatesMissingParentDir covers the half of issue #118 that
// reversing the preference alone does not fix. The per-user candidate is
// <config dir>/Bacchus/fyne-client.json and nothing creates that Bacchus
// directory on a machine where this client has never saved; os.WriteFile does
// not create parents, so the first save would have failed with "no such file
// or directory" instead of "permission denied" - the same broken first-run,
// one errno over.
func TestSaveConfigCreatesMissingParentDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	path := DefaultConfigPath()
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("parent of %q already exists (Stat err = %v); this test needs it missing", path, err)
	}

	if err := SaveConfig(path, Config{DNS: "1.1.1.1:53"}); err != nil {
		t.Fatalf("SaveConfig into a missing directory: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var readBack Config
	if err := json.Unmarshal(b, &readBack); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if readBack.DNS != "1.1.1.1:53" {
		t.Fatalf("DNS = %q, want %q", readBack.DNS, "1.1.1.1:53")
	}

	// The file holds TURNPass and VolunteerExitKey, so neither it nor the
	// directory this just created may be readable by other users. Unix modes
	// only - Windows does not carry them.
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config file mode = %o, want 600", perm)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("created directory mode = %o, want 700", perm)
	}
}

// TestLoadConfigNotExist confirms the "fresh install" contract LoadConfig's
// doc promises: os.ErrNotExist (wrapped), empty path, zero Config - not a
// panic or some other error shape main.go would have to special-case.
func TestLoadConfigNotExist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, path, err := LoadConfig()
	if !os.IsNotExist(err) {
		t.Fatalf("LoadConfig err = %v, want os.ErrNotExist", err)
	}
	if path != "" {
		t.Fatalf("LoadConfig path = %q, want empty", path)
	}
}

// ---------------------------------------------------------------------------
// The account service (bacchus#163, ADR-0056)
// ---------------------------------------------------------------------------

// TestAccountServiceFieldsRoundTrip pins the JSON keys, because they are the
// operator's interface: a key renamed here is a config file that silently stops
// naming an account service, which reads exactly like a deployment that has
// none.
func TestAccountServiceFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bacchus-fyne.config.json")
	want := Config{
		AccountServiceURL:      "https://account.example:8443",
		AccountServiceAudience: "account.example",
		AccountServiceCA:       "/etc/bacchus/account-ca.pem",
		DeviceCredDir:          "/var/lib/bacchus/device",
		ClaimCode:              "BC1-EXAMPLE",
		DeviceLabel:            "laptop",
	}
	if err := SaveConfig(path, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"accountServiceUrl", "accountServiceAudience", "accountServiceCa", "deviceCredDir", "claimCode", "deviceLabel"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("config file has no %q key", key)
		}
	}
	var got Config
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestAccountServiceConfiguredAndItsDefaults(t *testing.T) {
	var empty Config
	if empty.AccountServiceConfigured() {
		t.Fatal("an empty config claims to name an account service")
	}
	if got := empty.EffectiveDeviceLabel(); got != DefaultDeviceLabel {
		t.Fatalf("EffectiveDeviceLabel = %q", got)
	}
	// The default label must say nothing about the machine: it travels to the
	// service in the clear and is stored there durably.
	host, _ := os.Hostname()
	if host != "" && strings.Contains(DefaultDeviceLabel, host) {
		t.Fatal("the default device label carries this machine's hostname")
	}

	c := Config{AccountServiceURL: "  https://a.example  ", DeviceLabel: "  laptop  ", DeviceCredDir: "  /d  "}
	if !c.AccountServiceConfigured() {
		t.Fatal("a URL with surrounding whitespace read as no account service")
	}
	if got := c.EffectiveDeviceLabel(); got != "laptop" {
		t.Fatalf("EffectiveDeviceLabel = %q", got)
	}
	if got := c.EffectiveDeviceCredDir(); got != "/d" {
		t.Fatalf("EffectiveDeviceCredDir = %q", got)
	}
}

// TestAnUpgradedClientKeepsWorkingOnTheOlderAccountServiceKey is bacchus#192's
// back-compat half (wave ruling R5). The single-string key is on installed
// clients' disks today; an upgrade that stopped reading it would look like
// nothing at all for six hours and then take every one of those devices off the
// network, at the far end of a change the user never saw.
func TestAnUpgradedClientKeepsWorkingOnTheOlderAccountServiceKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bacchus-fyne.config.json")
	// Exactly what an installed client's file holds: the older key, and no sign
	// that a list was ever a possibility.
	onDisk := `{
	  "coordinators": ["203.0.113.10:8080"],
	  "accountServiceUrl": "https://account.example:8443",
	  "accountServiceAudience": "account.example",
	  "accountServiceCa": "/etc/bacchus/account-ca.pem"
	}`
	if err := os.WriteFile(path, []byte(onDisk), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if !c.AccountServiceConfigured() {
		t.Fatal("an upgraded client reads its own config file as naming no account service")
	}
	if got := c.AccountServiceAddresses(); len(got) != 1 || got[0] != "https://account.example:8443" {
		t.Fatalf("AccountServiceAddresses() = %v, want the single older key's value", got)
	}

	// And a Settings save does not migrate the file out from under it. A load
	// that rewrote what it read would take a downgrade away from anyone who tried
	// this build, and the whole point of one release of overlap is that both
	// builds keep working.
	if err := SaveConfig(path, c); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(after, &raw); err != nil {
		t.Fatal(err)
	}
	if got := raw["accountServiceUrl"]; got != "https://account.example:8443" {
		t.Fatalf("after a save the older key is %v; nothing may migrate the user's file", got)
	}
}

// TestTheAddressListWinsOverTheOlderKey: the two keys are resolved at the point
// of use, and the list is what an operator edits to move. Folding the older value
// in would resurrect exactly the address they were moving away from — at the
// front, since it is the one this client already believed in.
func TestTheAddressListWinsOverTheOlderKey(t *testing.T) {
	c := Config{
		AccountServiceURLs: []string{" https://new.example:8443 ", "", "https://spare.example:8443"},
		AccountServiceURL:  "https://old.example:8443",
	}
	got := c.AccountServiceAddresses()
	want := []string{"https://new.example:8443", "https://spare.example:8443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AccountServiceAddresses() = %v, want %v — trimmed, blanks dropped, older key ignored", got, want)
	}

	// A config that names only a list is a complete configuration, and one that
	// names neither still reads as a deployment with no account service.
	if !(Config{AccountServiceURLs: []string{"https://a.example"}}).AccountServiceConfigured() {
		t.Fatal("a list-only config reads as naming no account service")
	}
	if (Config{AccountServiceURLs: []string{" "}}).AccountServiceConfigured() {
		t.Fatal("a list of blanks reads as naming an account service")
	}
}

// TestANewConfigDoesNotAcquireTheDeprecatedKey: omitempty on the older key keeps
// a client that never had one from learning the deprecated spelling from its own
// saved file.
func TestANewConfigDoesNotAcquireTheDeprecatedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bacchus-fyne.config.json")
	if err := SaveConfig(path, Config{AccountServiceURLs: []string{"https://account.example:8443"}}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["accountServiceUrl"]; ok {
		t.Fatal("a fresh config file carries the deprecated single-address key")
	}
	if _, ok := raw["accountServiceUrls"]; !ok {
		t.Fatal("a fresh config file has no accountServiceUrls key")
	}
}

// TestEffectiveDeviceCredDirDefaultsPerUserNotBesideTheExecutable: the
// exe-adjacent path is issue #118's failure again — a device key written next to
// a binary in a system directory fails on permissions for the ordinary user, and
// core's documented failure mode for an unwritable key path is a hard
// construction error at connect.
func TestEffectiveDeviceCredDirDefaultsPerUserNotBesideTheExecutable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	got := Config{}.EffectiveDeviceCredDir()
	if got == "" {
		t.Fatal("no default device-credential directory")
	}
	if !strings.HasPrefix(got, dir) {
		t.Fatalf("default device dir = %q, want it under the per-user config directory %q", got, dir)
	}
	exe, err := os.Executable()
	if err == nil && filepath.Dir(got) == filepath.Dir(exe) {
		t.Fatalf("default device dir sits beside the executable: %q", got)
	}
}

// TestClearClaimCodeErasesOnlyTheClaimCode: it re-reads before it writes, so a
// settings save that landed between the connect starting and the enrollment
// finishing is not reverted.
func TestClearClaimCodeErasesOnlyTheClaimCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	perUser := filepath.Join(dir, "Bacchus")
	if err := os.MkdirAll(perUser, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(perUser, "fyne-client.json")
	start := Config{
		Coordinators: []string{"c.example:8080"},
		Country:      "NL",
		ClaimCode:    "BC1-SPENT",
		DeviceLabel:  "laptop",
	}
	if err := SaveConfig(path, start); err != nil {
		t.Fatal(err)
	}

	// Something else edits the file while the connect is in flight.
	edited := start
	edited.Country = "DE"
	if err := SaveConfig(path, edited); err != nil {
		t.Fatal(err)
	}

	if err := ClearClaimCode(); err != nil {
		t.Fatalf("ClearClaimCode: %v", err)
	}
	got, _, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.ClaimCode != "" {
		t.Fatalf("the claim code survived: %q", got.ClaimCode)
	}
	if got.Country != "DE" {
		t.Fatalf("country = %q; the concurrent edit was reverted", got.Country)
	}
	if len(got.Coordinators) != 1 || got.DeviceLabel != "laptop" {
		t.Fatalf("other fields were disturbed: %+v", got)
	}
}

// TestClearClaimCodeOnAFreshInstallIsNotAnError: nothing on disk holds a spent
// claim code, which is the state this function exists to reach.
func TestClearClaimCodeOnAFreshInstallIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := ClearClaimCode(); err != nil {
		t.Fatalf("ClearClaimCode with no config file: %v", err)
	}
}

// deprecatedConfigKeys are read for back-compat and deliberately kept OUT of the
// template. The template is what a new deployment copies, so a key that exists
// only so an existing installation keeps working would teach the spelling being
// retired to everyone who has no reason to use it.
//
// Naming them here rather than skipping "anything with omitempty" is the point:
// the exemption is a list somebody has to add to on purpose, and the test below
// checks both directions, so a deprecated key cannot drift back into the template
// and a live key cannot be excused from it by accident.
var deprecatedConfigKeys = map[string]string{
	// bacchus#192: superseded by accountServiceUrls, read for one release.
	"accountServiceUrl": "accountServiceUrls",
}

// TestTheExampleConfigCarriesEveryFieldAJSONConfigCanSet: the template is what
// an operator copies, and a field missing from it is a field nobody knows to
// set — which is how AdmissionPubKey came to be unreachable before #93.
func TestTheExampleConfigCarriesEveryFieldAJSONConfigCanSet(t *testing.T) {
	b, err := os.ReadFile("../../bacchus-fyne.config.example.json")
	if err != nil {
		t.Fatalf("read the example config: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("the example config is not valid JSON: %v", err)
	}
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		_, ok := raw[name]
		if replacement, deprecated := deprecatedConfigKeys[name]; deprecated {
			if ok {
				t.Errorf("bacchus-fyne.config.example.json still offers %q, which is superseded by %q — a new deployment copying the template would start on the key being retired", name, replacement)
			}
			continue
		}
		if !ok {
			t.Errorf("bacchus-fyne.config.example.json has no %q key, so an operator copying the template cannot discover it", name)
		}
	}
}
