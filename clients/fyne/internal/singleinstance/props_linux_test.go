//go:build linux

package singleinstance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// guarded and fileScoped describe this platform's implementation to the
// portable tests. They are constants per build tag rather than a runtime
// question, so a platform that gains a guard has to come here and say so.
const (
	guarded    = true
	fileScoped = true
)

// holdLockEnv makes the test binary re-enter itself as a stand-in for a second
// client. It has to be a real process, because the property being asserted is
// that the KERNEL releases the lock when a process dies — which is what makes
// this guard safe after the killed client of bacchus#115, and which an
// in-process test cannot observe at all.
const holdLockEnv = "BACCHUS_TEST_HOLD_LOCK_DIR"

// TestMain is the subprocess entry point. With holdLockEnv set it takes the
// lock, reports that it has it, and then dies WITHOUT releasing anything —
// os.Exit runs no defers, which is exactly the abnormal exit being modelled.
func TestMain(m *testing.M) {
	dir := os.Getenv(holdLockEnv)
	if dir == "" {
		os.Exit(m.Run())
	}
	if _, err := Acquire(dir); err != nil {
		os.Stdout.WriteString("acquire failed: " + err.Error() + "\n")
		os.Exit(2)
	}
	os.Stdout.WriteString("held\n")
	os.Exit(0)
}

// TestAKilledHolderReleasesTheSlot is the crash case. A guard that survived the
// process would leave a machine on which Bacchus can never be started again,
// and the recovery would be deleting a file nobody has been told about.
func TestAKilledHolderReleasesTheSlot(t *testing.T) {
	dir := t.TempDir()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), holdLockEnv+"="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper process: %v: %s", err, out)
	}
	if string(out) != "held\n" {
		t.Fatalf("helper process said %q, want it to have taken the lock", out)
	}
	if _, err := os.Stat(filepath.Join(dir, LockFileName)); err != nil {
		t.Fatalf("the helper left no lock file behind: %v", err)
	}

	// The exit above already reaped the process, so the lock is gone by the
	// time Wait returned. No sleep, no poll: if this ever needs one, the guard
	// is not kernel-released and the doc comment is wrong.
	release, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after the holder died: %v — the slot is stuck", err)
	}
	release()
}

// TestAConcurrentHolderKeepsTheSlot is the same machinery pointed the other
// way, so that TestAKilledHolderReleasesTheSlot cannot pass by the lock never
// having been taken at all.
func TestAConcurrentHolderKeepsTheSlot(t *testing.T) {
	dir := t.TempDir()

	release, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer release()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), holdLockEnv+"="+dir)
	done := make(chan struct {
		out []byte
		err error
	}, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		done <- struct {
			out []byte
			err error
		}{out, err}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("a second process took the lock while this one holds it: %s", r.out)
		}
		if !strings.Contains(string(r.out), "acquire failed: "+ErrAlreadyRunning.Error()) {
			t.Fatalf("second process failed for the wrong reason: %v: %s", r.err, r.out)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the second process neither took the lock nor refused — Acquire is blocking, and a client that hangs at launch is worse than one that says no")
	}
}
