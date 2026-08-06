package singleinstance

import (
	"strings"
	"testing"
)

// TestMutexNamesAreUsableByInnoSetup checks the properties bacchus.iss's
// AppMutex needs and that nothing else would catch.
//
// AppMutex takes a COMMA-SEPARATED list, so a comma inside a name silently
// splits it into two names neither of which the client ever creates — the
// installer then never finds a running client and #185's uninstaller half comes
// back with no error anywhere. The Global\ prefix is the other half: Inno looks
// up exactly the string it is given, so a name created in the global namespace
// and declared without the prefix is a different name.
func TestMutexNamesAreUsableByInnoSetup(t *testing.T) {
	for _, name := range []string{GlobalMutexName, SessionMutexName} {
		if name == "" {
			t.Fatal("an empty mutex name would match every other empty name on the machine")
		}
		if strings.ContainsAny(name, ",\"") {
			t.Errorf("%q contains a character AppMutex's list syntax reserves", name)
		}
	}
	if !strings.HasPrefix(GlobalMutexName, `Global\`) {
		t.Errorf("GlobalMutexName = %q, want the Global\\ namespace prefix", GlobalMutexName)
	}
	if strings.Contains(SessionMutexName, `\`) {
		t.Errorf("SessionMutexName = %q, want a bare name with no namespace prefix", SessionMutexName)
	}
	if GlobalMutexName == SessionMutexName {
		t.Error("the two names are identical, so only one namespace is actually guarded")
	}
	// The session name is the global one without its prefix. Not cosmetic: it
	// is what makes the pair readable as one guard in the .iss, where they sit
	// on a single AppMutex line with nothing to explain them.
	if got := strings.TrimPrefix(GlobalMutexName, `Global\`); got != SessionMutexName {
		t.Errorf("GlobalMutexName without its prefix is %q, want SessionMutexName %q", got, SessionMutexName)
	}
}

// TestSecondAcquireIsRefused is the defect itself: two clients on one machine.
//
// It runs on every platform. On the no-guard platforms it asserts the
// documented stub behaviour instead, so that the day one of them grows an
// Enforcer this test is already sitting on the assumption that has to change.
func TestSecondAcquireIsRefused(t *testing.T) {
	dir := t.TempDir()

	first, err := Acquire(dir)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer first()

	second, err := Acquire(dir)
	if second != nil {
		defer second()
	}
	if !guarded {
		if err != nil {
			t.Errorf("the unguarded platform stub returned %v, want nil", err)
		}
		return
	}
	if err != ErrAlreadyRunning {
		t.Fatalf("second Acquire returned %v, want ErrAlreadyRunning — two clients can arm at once", err)
	}
}

// TestReleaseLetsTheNextClientIn is the other direction, and it is the one that
// matters after a crash: a slot that is never given back is a client that can
// never be restarted.
func TestReleaseLetsTheNextClientIn(t *testing.T) {
	if !guarded {
		t.Skip("no guard on this platform")
	}
	dir := t.TempDir()

	first, err := Acquire(dir)
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	first()

	second, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after release: %v — the slot was not given back", err)
	}
	second()
}

// TestSeparateDirectoriesDoNotCollide pins the scope of the file-based guard:
// it is per-directory, so a test, a portable copy and an installed copy pointed
// at different per-user directories do not fight. On Windows the guard is a
// kernel name and ignores the directory entirely, which is the wider scope
// #185 needs there and is why this assertion is Linux-shaped.
func TestSeparateDirectoriesDoNotCollide(t *testing.T) {
	if !fileScoped {
		t.Skip("the guard on this platform is not scoped to a directory")
	}
	a, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatalf("Acquire A: %v", err)
	}
	defer a()
	b, err := Acquire(t.TempDir())
	if err != nil {
		t.Fatalf("Acquire B: %v — two unrelated directories are sharing one guard", err)
	}
	defer b()
}
