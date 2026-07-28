//go:build linux

package appstate

import (
	"os"
	"strings"
	"testing"
)

// TestSetLaunchOnBootLinux exercises the real XDG autostart mechanism against
// a temporary XDG_CONFIG_HOME (t.Setenv), so it never touches the actual
// account's autostart directory — unlike the registry Run key on Windows,
// there is no single shared per-machine resource here that needs an
// unconditional cleanup.
func TestSetLaunchOnBootLinux(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	path, err := autostartDesktopFilePath()
	if err != nil {
		t.Fatalf("autostartDesktopFilePath: %v", err)
	}
	if !strings.HasPrefix(path, dir) {
		t.Fatalf("autostartDesktopFilePath() = %q, want a path under the fake XDG_CONFIG_HOME %q", path, dir)
	}

	// Disabling with nothing registered is a no-op, not an error.
	if err := SetLaunchOnBoot(false); err != nil {
		t.Fatalf("SetLaunchOnBoot(false) with nothing registered: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("desktop file present after disabling with nothing registered (stat err: %v)", err)
	}

	if err := SetLaunchOnBoot(true); err != nil {
		t.Fatalf("SetLaunchOnBoot(true): %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read desktop file: %v", err)
	}
	content := string(b)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	for _, want := range []string{
		"[Desktop Entry]",
		"Type=Application",
		`Exec="` + exe + `"`,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("desktop entry missing %q; got:\n%s", want, content)
		}
	}

	// Enabling again (the reconcile-at-startup call main.go makes every run)
	// must not error just because the file already exists, and must still
	// contain a well-formed entry afterward.
	if err := SetLaunchOnBoot(true); err != nil {
		t.Fatalf("SetLaunchOnBoot(true) a second time: %v", err)
	}
	if b2, err := os.ReadFile(path); err != nil || string(b2) != content {
		t.Fatalf("second SetLaunchOnBoot(true) changed the entry: err=%v, content=%q", err, string(b2))
	}

	if err := SetLaunchOnBoot(false); err != nil {
		t.Fatalf("SetLaunchOnBoot(false): %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("desktop file still present after SetLaunchOnBoot(false) (stat err: %v)", err)
	}

	// Disabling twice in a row (already absent) must also not error.
	if err := SetLaunchOnBoot(false); err != nil {
		t.Fatalf("SetLaunchOnBoot(false) a second time: %v", err)
	}
}
