package appstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
