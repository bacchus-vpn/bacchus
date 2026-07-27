//go:build windows

package appstate

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// redirectRunKeyForTest points runKeyPath at a private test-only key (issue
// #170) instead of the real Run key, so a hard-killed test run can never
// leave a stale autostart entry in the developer/CI account's actual startup
// list. These tests exercise the real registry.CreateKey/OpenKey/
// SetStringValue/GetStringValue/DeleteValue/DeleteKey round trip — that's
// what they're proving, not specifically the real Run key's location.
// Cleanup deletes the value, then the whole test key, then restores the
// original path, regardless of which case ran or whether it failed partway
// through.
func redirectRunKeyForTest(t *testing.T) {
	t.Helper()
	orig := runKeyPath
	runKeyPath = `Software\BacchusFyneAutostartTest`
	t.Cleanup(func() {
		if k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE); err == nil {
			_ = k.DeleteValue(autostartValueName)
			k.Close()
		}
		_ = registry.DeleteKey(registry.CURRENT_USER, runKeyPath)
		runKeyPath = orig
	})
}

// readRunValue is the test's own read path, independent of SetLaunchOnBoot,
// so the assertions below prove what actually landed in the registry rather
// than re-deriving it from the same code under test.
func readRunValue(t *testing.T) (string, bool) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("OpenKey(%s): %v", runKeyPath, err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue(autostartValueName)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatalf("GetStringValue(%s): %v", autostartValueName, err)
	}
	return v, true
}

// TestSetLaunchOnBootWindows exercises a real registry round trip against
// the redirected test key (issue #170 — see redirectRunKeyForTest).
func TestSetLaunchOnBootWindows(t *testing.T) {
	redirectRunKeyForTest(t)

	// Disabling with nothing registered is a no-op, not an error.
	if err := SetLaunchOnBoot(false); err != nil {
		t.Fatalf("SetLaunchOnBoot(false) with nothing registered: %v", err)
	}
	if _, present := readRunValue(t); present {
		t.Fatal("value present after disabling with nothing registered")
	}

	if err := SetLaunchOnBoot(true); err != nil {
		t.Fatalf("SetLaunchOnBoot(true): %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	want := `"` + exe + `"`
	got, present := readRunValue(t)
	if !present {
		t.Fatal("value absent after SetLaunchOnBoot(true)")
	}
	if got != want {
		t.Fatalf("registry value = %q, want %q (quoted executable path)", got, want)
	}

	// Enabling again (the reconcile-at-startup call main.go makes every run)
	// must not error just because the value already exists.
	if err := SetLaunchOnBoot(true); err != nil {
		t.Fatalf("SetLaunchOnBoot(true) a second time: %v", err)
	}

	if err := SetLaunchOnBoot(false); err != nil {
		t.Fatalf("SetLaunchOnBoot(false): %v", err)
	}
	if _, present := readRunValue(t); present {
		t.Fatal("value still present after SetLaunchOnBoot(false)")
	}

	// Disabling twice in a row (already absent) must also not error.
	if err := SetLaunchOnBoot(false); err != nil {
		t.Fatalf("SetLaunchOnBoot(false) a second time: %v", err)
	}
}

// TestLaunchOnBootActiveWindows pins LaunchOnBootActive's presence check
// (issue #170) against the redirected test key.
func TestLaunchOnBootActiveWindows(t *testing.T) {
	redirectRunKeyForTest(t)

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

// TestReconcileLaunchOnBootWindows is issue #170's fix, proven against the
// real (redirected) registry: an out-of-app disable (the Run value hand-
// removed, or simply never created) must not be silently resurrected.
func TestReconcileLaunchOnBootWindows(t *testing.T) {
	redirectRunKeyForTest(t)

	// LaunchOnBoot=false always ensures the entry is absent, unconditionally.
	got, err := ReconcileLaunchOnBoot(Config{LaunchOnBoot: false})
	if err != nil {
		t.Fatalf("ReconcileLaunchOnBoot({false}): %v", err)
	}
	if got.LaunchOnBoot {
		t.Fatal("ReconcileLaunchOnBoot({false}).LaunchOnBoot = true")
	}
	if active, _ := LaunchOnBootActive(); active {
		t.Fatal("entry present after ReconcileLaunchOnBoot({false})")
	}

	// LaunchOnBoot=true with the entry present: refreshes it, stays true.
	if err := SetLaunchOnBoot(true); err != nil {
		t.Fatalf("SetLaunchOnBoot(true): %v", err)
	}
	got, err = ReconcileLaunchOnBoot(Config{LaunchOnBoot: true})
	if err != nil {
		t.Fatalf("ReconcileLaunchOnBoot({true}) with the entry present: %v", err)
	}
	if !got.LaunchOnBoot {
		t.Fatal("ReconcileLaunchOnBoot corrected LaunchOnBoot to false despite the entry being present")
	}
	if active, _ := LaunchOnBootActive(); !active {
		t.Fatal("entry absent after ReconcileLaunchOnBoot({true}) with it already present")
	}

	// LaunchOnBoot=true with the entry ABSENT (an out-of-app disable): this
	// is the fix — corrected to false instead of recreating the entry.
	if err := SetLaunchOnBoot(false); err != nil {
		t.Fatalf("SetLaunchOnBoot(false): %v", err)
	}
	got, err = ReconcileLaunchOnBoot(Config{LaunchOnBoot: true})
	if err != nil {
		t.Fatalf("ReconcileLaunchOnBoot({true}) with the entry absent: %v", err)
	}
	if got.LaunchOnBoot {
		t.Fatal("ReconcileLaunchOnBoot recreated an entry the user removed out of band")
	}
	if active, _ := LaunchOnBootActive(); active {
		t.Fatal("ReconcileLaunchOnBoot({true}) with the entry absent must not create one")
	}
}
