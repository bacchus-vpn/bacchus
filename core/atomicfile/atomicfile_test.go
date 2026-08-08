package atomicfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The tests in this file are issue #188's two defects and the properties that
// have to survive the consolidation. They come at it from the angles that are
// actually distinct:
//
//   - what the implementation DID (it replaced the file rather than rewriting
//     it), which is the assertion that fails the moment this becomes an
//     os.WriteFile again;
//   - what two CONCURRENT writers can install, which is the defect a fixed
//     staged name made reachable;
//   - what a reader of the STAGED file can see while a write is in flight,
//     which is the mode ordering;
//   - what a failed write leaves behind.

func mustWrite(t *testing.T, path string, b []byte, perm os.FileMode) {
	t.Helper()
	if err := Write(path, b, perm); err != nil {
		t.Fatalf("Write(%s): %v", path, err)
	}
}

// The headline property: the live file is never opened for writing, so a reader
// that already has it open keeps reading a whole file. os.WriteFile fails this
// — it truncates the very inode the reader holds.
func TestWriteReplacesTheFileRatherThanRewritingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	first := []byte(`{"generation":1}`)
	mustWrite(t, path, first, 0o600)

	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	mustWrite(t, path, []byte(`{"generation":2}`), 0o600)

	// The held handle still names the old inode, whole.
	b := make([]byte, len(first))
	if _, err := held.ReadAt(b, 0); err != nil {
		t.Fatalf("the file a reader already held was destroyed by the next write: %v", err)
	}
	if !bytes.Equal(b, first) {
		t.Errorf("a reader holding the previous file saw %q, want %q — the live file was rewritten in place", b, first)
	}
	// And the path itself now names the new one.
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != `{"generation":2}` {
		t.Errorf("installed %q, want the second generation", cur)
	}
}

// Issue #188's second defect, and the one a fixed staged name made reachable:
// two savers of the same file staged into ONE ".tmp" and the rename installed
// the mixture. os.CreateTemp makes that unrepresentable — every writer stages
// into a file it created with O_EXCL under a name nothing else will pick.
//
// The assertion is that every byte sequence ever observed at the path is
// EXACTLY one writer's payload. The payloads differ in length and in every byte,
// so any interleaving of two of them fails the check whichever way it happened
// to interleave.
//
// The reader loop runs alongside rather than after: the failure this covers is
// a moment, not an end state, and a test that only inspected the final file
// would pass over a whole run of mangled generations.
func TestConcurrentWritersNeverInstallAMixture(t *testing.T) {
	const (
		writers = 8
		rounds  = 40
	)
	dir := t.TempDir()
	path := filepath.Join(dir, "contended.json")

	payloads := make([][]byte, writers)
	for i := range payloads {
		// Distinct byte AND distinct length, so a mixture is detectable
		// whichever writer's bytes land where.
		payloads[i] = bytes.Repeat([]byte{byte('a' + i)}, 512+i*997)
	}
	whole := func(b []byte) bool {
		for _, p := range payloads {
			if bytes.Equal(b, p) {
				return true
			}
		}
		return false
	}

	var readersDone, writersDone sync.WaitGroup
	stop := make(chan struct{})
	var bad atomic.Int64
	var reads atomic.Int64

	for r := 0; r < 2; r++ {
		readersDone.Add(1)
		go func() {
			defer readersDone.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				b, err := os.ReadFile(path)
				if err != nil {
					continue // nothing installed yet
				}
				reads.Add(1)
				if !whole(b) {
					bad.Add(1)
					t.Errorf("a reader observed %d bytes that are not any writer's payload (first byte %q, last %q) — two savers interleaved into one staged file",
						len(b), b[0], b[len(b)-1])
					return
				}
			}
		}()
	}

	for i := 0; i < writers; i++ {
		writersDone.Add(1)
		go func(i int) {
			defer writersDone.Done()
			for n := 0; n < rounds; n++ {
				if err := Write(path, payloads[i], 0o600); err != nil {
					t.Errorf("writer %d round %d: %v", i, n, err)
					return
				}
			}
		}(i)
	}

	writersDone.Wait()
	close(stop)
	readersDone.Wait()

	if reads.Load() == 0 {
		t.Error("no reader ever observed the file; this test proved nothing")
	}
	if bad.Load() != 0 {
		t.Errorf("%d mangled generations observed", bad.Load())
	}

	// Nothing staged survives a run where every write completed.
	assertNoDebris(t, dir, path, "after a contended run")
}

// A completed write cleans up after itself. Debris from a SUCCESSFUL save is a
// leak rather than a crash artifact, and it would accumulate one file per write.
func assertNoDebris(t *testing.T, dir, path, when string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	prefix := "." + filepath.Base(path) + ".tmp"
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			t.Errorf("%s: %q was left behind", when, e.Name())
		}
	}
}

// The staged name has to be recognisable as debris and impossible to mistake
// for the file itself, because a writer killed between staging and rename
// cannot clean up after itself. Asserted by making the rename fail: a directory
// squatting on the target defeats os.Rename on every platform, and the staged
// file is then removed on the way out.
func TestAFailedInstallLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	err := Write(path, []byte("hello"), 0o600)
	if err == nil {
		t.Fatal("renaming over a directory must fail")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error must name the target it failed to install: %v", err)
	}
	assertNoDebris(t, dir, path, "after a failed install")
}

// perm is applied to the INSTALLED file every time, not only when creating it.
// os.WriteFile left an existing file's mode alone, so a file that had been
// widened stayed wide; this narrows it back on every write.
func TestPermIsAppliedOverAnExistingWiderFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows expresses file modes through ACLs; os.Chmod only toggles the read-only attribute")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, []byte("new"), 0o600)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("installed mode %v, want 0600 — a replaced file must carry the mode it was written with", got)
	}
}

// The other direction, which is cmd/bacchus-netd's: /etc/resolv.conf must be
// world-readable, so a helper that could only narrow would be no use there.
func TestAWideningPermIsHonoured(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows expresses file modes through ACLs; os.Chmod only toggles the read-only attribute")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	mustWrite(t, path, []byte("nameserver 10.0.0.53\n"), 0o644)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("installed mode %v, want 0644", got)
	}
}

// The mode ordering, which is the one thing the nine copies disagreed about.
// perm is applied AFTER the bytes, so a widening perm never exposes an
// INCOMPLETE staged file: it is 0600 (os.CreateTemp's mode) for as long as it
// is short, and 0644 only once it is whole.
//
// This test cannot force the window open — there is no hook inside Write — so
// it widens it with a payload large enough to be caught by a polling watcher
// and asserts the negative: nothing world-readable was ever seen incomplete. It
// therefore never fails spuriously, and it does report whether it managed to
// observe the staged file at all, so a run that proved nothing says so rather
// than reading as evidence.
func TestAStagedFileIsNotWorldReadableWhileIncomplete(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows expresses file modes through ACLs; os.Chmod only toggles the read-only attribute")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	body := bytes.Repeat([]byte("nameserver 10.0.0.53\n"), 800_000) // ~16 MiB

	stop := make(chan struct{})
	done := make(chan struct{})
	var seenIncomplete, violations atomic.Int64
	go func() {
		defer close(done)
		prefix := "." + filepath.Base(path) + ".tmp"
		for {
			select {
			case <-stop:
				return
			default:
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !strings.HasPrefix(e.Name(), prefix) {
					continue
				}
				fi, err := e.Info()
				if err != nil {
					continue
				}
				if fi.Size() >= int64(len(body)) {
					continue
				}
				seenIncomplete.Add(1)
				if fi.Mode().Perm()&0o077 != 0 {
					violations.Add(1)
				}
			}
		}
	}()

	mustWrite(t, path, body, 0o644)
	close(stop)
	<-done

	if violations.Load() != 0 {
		t.Errorf("a staged file was world-readable while still short, %d times — perm is being applied before the bytes", violations.Load())
	}
	if seenIncomplete.Load() == 0 {
		t.Log("note: the watcher never caught the staged file mid-write, so this run only confirms the final mode")
	}
}

// It does not create parent directories. Three callers want that and three
// deliberately do not, so the decision stays at the call site — and for a tool
// writing into a secrets directory, a missing directory is an error rather than
// something a save quietly conjures.
func TestWriteDoesNotCreateParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "state.json")
	if err := Write(path, []byte("x"), 0o600); err == nil {
		t.Fatal("writing into a directory that does not exist must fail rather than create it")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("the parent directory was created: %v", err)
	}
}

// A symlink at the target is REPLACED rather than written through, which is a
// real change from os.WriteFile and worth pinning: it is what stops a symlink
// planted in a state directory from redirecting a 0600 write somewhere else.
func TestASymlinkTargetIsReplaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink on Windows needs a privilege the test runner may not hold")
	}
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(elsewhere, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Fatal(err)
	}

	mustWrite(t, path, []byte("installed"), 0o600)

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the symlink survived; the write followed it instead of replacing it")
	}
	if b, err := os.ReadFile(elsewhere); err != nil || string(b) != "untouched" {
		t.Errorf("the symlink's target was written through: %q, %v", b, err)
	}
}

// WriteDurable installs exactly what Write installs. The durability it adds is
// a property of a power loss and cannot be asserted from inside a process; what
// is asserted here is that the extra step neither changes the result nor fails
// on an ordinary directory.
func TestWriteDurableInstallsTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revocations.json")
	if err := WriteDurable(path, []byte(`{"revoked":[]}`), 0o600); err != nil {
		t.Fatalf("WriteDurable: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != `{"revoked":[]}` {
		t.Fatalf("installed %q, %v", b, err)
	}
	assertNoDebris(t, dir, path, "after a durable write")
}

func TestSyncDirReportsAMissingDirectory(t *testing.T) {
	if err := SyncDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("SyncDir on a directory that does not exist must fail")
	}
}

// Every error names the path it failed on, because the callers wrap with a
// package prefix and nothing else in the message identifies the file.
func TestErrorsNameTheirPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing", "state.json")
	err := Write(missing, []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected a failure")
	}
	if !strings.Contains(err.Error(), filepath.Dir(missing)) {
		t.Errorf("a staging failure must name the directory it tried to stage in: %v", err)
	}
}

func BenchmarkWrite(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "state.json")
	body := []byte(fmt.Sprintf(`{"seq":%d}`, 1))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Write(path, body, 0o600); err != nil {
			b.Fatal(err)
		}
	}
}
