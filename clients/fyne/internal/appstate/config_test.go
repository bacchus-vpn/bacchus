package appstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}
	path := filepath.Join(filepath.Dir(exe), "bacchus-fyne.config.json")
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("%s already exists - refusing to overwrite it", path)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Skipf("cannot write beside the test binary: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })
	return path
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
