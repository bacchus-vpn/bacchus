//go:build windows

package appstate

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows/registry"
)

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

// TestSetLaunchOnBootWindows exercises the real per-user registry Run key -
// this modifies the actual developer/CI account's HKEY_CURRENT_USER, so
// every path through it must leave the value exactly as it found it
// (t.Cleanup unconditionally deletes it, regardless of which case ran or
// whether it failed partway through).
func TestSetLaunchOnBootWindows(t *testing.T) {
	t.Cleanup(func() {
		k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		_ = k.DeleteValue(autostartValueName)
	})

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
