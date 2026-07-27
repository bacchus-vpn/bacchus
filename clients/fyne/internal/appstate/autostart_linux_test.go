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

// TestLaunchOnBootActiveLinux pins LaunchOnBootActive's presence check
// (issue #170) against a temporary XDG_CONFIG_HOME.
func TestLaunchOnBootActiveLinux(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	active, err := LaunchOnBootActive()
	if err != nil {
		t.Fatalf("LaunchOnBootActive with nothing registered: %v", err)
	}
	if active {
		t.Fatal("LaunchOnBootActive() = true with nothing registered")
	}

	if err := SetLaunchOnBoot(true); err != nil {
		t.Fatalf("SetLaunchOnBoot(true): %v", err)
	}
	if active, err = LaunchOnBootActive(); err != nil {
		t.Fatalf("LaunchOnBootActive after SetLaunchOnBoot(true): %v", err)
	} else if !active {
		t.Fatal("LaunchOnBootActive() = false right after SetLaunchOnBoot(true)")
	}

	if err := SetLaunchOnBoot(false); err != nil {
		t.Fatalf("SetLaunchOnBoot(false): %v", err)
	}
	if active, err = LaunchOnBootActive(); err != nil {
		t.Fatalf("LaunchOnBootActive after SetLaunchOnBoot(false): %v", err)
	} else if active {
		t.Fatal("LaunchOnBootActive() = true right after SetLaunchOnBoot(false)")
	}
}

// TestReconcileLaunchOnBootLinux is issue #170's fix, proven against a real
// (temporary) XDG autostart directory: a hand-deleted .desktop file must not
// be silently recreated.
func TestReconcileLaunchOnBootLinux(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path, err := autostartDesktopFilePath()
	if err != nil {
		t.Fatalf("autostartDesktopFilePath: %v", err)
	}

	// LaunchOnBoot=false always ensures the file is absent, unconditionally.
	got, err := ReconcileLaunchOnBoot(Config{LaunchOnBoot: false})
	if err != nil {
		t.Fatalf("ReconcileLaunchOnBoot({false}): %v", err)
	}
	if got.LaunchOnBoot {
		t.Fatal("ReconcileLaunchOnBoot({false}).LaunchOnBoot = true")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("desktop file present after ReconcileLaunchOnBoot({false}) (stat err: %v)", err)
	}

	// LaunchOnBoot=true with the file present: refreshes it, stays true.
	if err := SetLaunchOnBoot(true); err != nil {
		t.Fatalf("SetLaunchOnBoot(true): %v", err)
	}
	got, err = ReconcileLaunchOnBoot(Config{LaunchOnBoot: true})
	if err != nil {
		t.Fatalf("ReconcileLaunchOnBoot({true}) with the file present: %v", err)
	}
	if !got.LaunchOnBoot {
		t.Fatal("ReconcileLaunchOnBoot corrected LaunchOnBoot to false despite the file being present")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("desktop file missing after ReconcileLaunchOnBoot({true}) with it already present: %v", err)
	}

	// LaunchOnBoot=true with the file hand-deleted (an out-of-app disable —
	// the common case on a minimal window manager with no startup-apps
	// settings UI of its own): corrected to false instead of recreating it.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove desktop file to simulate a hand-deletion: %v", err)
	}
	got, err = ReconcileLaunchOnBoot(Config{LaunchOnBoot: true})
	if err != nil {
		t.Fatalf("ReconcileLaunchOnBoot({true}) with the file hand-deleted: %v", err)
	}
	if got.LaunchOnBoot {
		t.Fatal("ReconcileLaunchOnBoot recreated a file the user hand-deleted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ReconcileLaunchOnBoot({true}) recreated the hand-deleted file (stat err: %v)", err)
	}
}
