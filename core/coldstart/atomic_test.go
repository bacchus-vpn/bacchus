package coldstart

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// The tests in this file are issue #178: the secrets file must be INSTALLED
// rather than truncated and refilled, because the only thing that writes it
// reads it first.
//
// They come at it from the angles that are actually distinct, since no one of
// them covers the others:
//
//   - what the implementation DID (it replaced the file rather than rewriting
//     it) — deterministic, and the assertion that fails the moment either writer
//     becomes an os.WriteFile again;
//   - what a concurrent RELOADER can observe while a save is in flight, which is
//     cmd/coordinator's reloadSecretsLoop;
//   - what a killed WRITER leaves on disk, which is the failure the card is
//     about: not a bad moment somebody reads, but a bad moment left lying around
//     permanently, with every previously issued secret inside it.
//
// Nothing here uses [GenerateSecret]. The fixtures are counters — a readable ID
// and a repeated byte — so that no value in this file or in any temporary file
// it writes could be mistaken for, or reused as, a real bootstrap secret.

// synthSecret builds an obviously-fake secret of the right length: byte i
// repeated. A real one is 32 bytes from crypto/rand.
func synthSecret(i int) []byte { return bytes.Repeat([]byte{byte(i)}, SecretLen) }

// synthStore builds a store of n entries whose IDs are prefix-0000, prefix-0001
// and so on. IDs are opaque map keys to [LoadMemStore] — only the secret is
// hex-decoded — so readable ones make a failure message answerable by eye.
func synthStore(prefix string, n int) *MemStore {
	s := NewMemStore()
	for i := 0; i < n; i++ {
		s.Add(fmt.Sprintf("%s-%04d", prefix, i), synthSecret(i))
	}
	return s
}

// storeIDs returns every secret ID in s, sorted. In-package so a test can look
// at the store's contents without [MemStore] growing an accessor that only tests
// would ever call.
func storeIDs(s *MemStore) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.secrets))
	for id := range s.secrets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// TestSaveFileReplacesTheFileRatherThanRewritingIt is the assertion that tells
// the two implementations apart, and it is about the INODE rather than the
// bytes.
//
// os.WriteFile — what this used to be — opens the live file with O_TRUNC and
// refills it, so between the truncate and the last byte the path holds a
// secrets file that is short or empty. A rename installs a file that was already
// complete before it had a name anybody reads, so no such moment exists.
//
// The hard link is the proof rather than a flourish. It is a second name for the
// inode the first save created, so the ORIGINAL bytes stay reachable whatever
// happens to path afterwards: if a later save ever writes through path again,
// the witness changes with it, which is exactly what must never happen. Skipped
// rather than failed where links are unavailable, because os.SameFile below
// answers the same question portably and the link is the sharper of the two, not
// the only one.
func TestSaveFileReplacesTheFileRatherThanRewritingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap-secrets.json")

	first := synthStore("issued", 1)
	if err := first.SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	witness := filepath.Join(dir, "witness.json")
	linked := os.Link(path, witness) == nil

	second := synthStore("issued", 2)
	if err := second.SaveFile(path); err != nil {
		t.Fatalf("SaveFile (second): %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat (second): %v", err)
	}
	if os.SameFile(before, after) {
		t.Error("the second save went into the file the first one created; a truncate-and-write is readable as an empty secrets file, and cmd/coldstart-issue's read-modify-write would leave it that way permanently")
	}
	if linked {
		old, err := LoadMemStore(witness)
		if err != nil {
			t.Fatalf("the file the first save created no longer parses, so the second save wrote through it: %v", err)
		}
		if _, ok := old.Lookup("issued-0001"); ok {
			t.Error("the second store was written INTO the file the first save created, so anything already reading that file saw it change underneath")
		}
	}

	loaded, err := LoadMemStore(path)
	if err != nil {
		t.Fatalf("LoadMemStore: %v", err)
	}
	if got := storeIDs(loaded); len(got) != 2 {
		t.Errorf("installed secrets file holds %v, want both entries", got)
	}
	assertNoStagedFiles(t, dir, path, "after a save that completed")
}

// TestSaveCacheReplacesTheFileRatherThanRewritingIt is the same assertion for
// the other writer in this package. Its stakes are lower and [SaveCache]'s doc
// says why it is atomic anyway; this is what would notice it quietly going back.
func TestSaveCacheReplacesTheFileRatherThanRewritingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.cache")

	if err := SaveCache(path, []byte("first opaque signed snapshot")); err != nil {
		t.Fatalf("SaveCache: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := SaveCache(path, []byte("second opaque signed snapshot, a different length")); err != nil {
		t.Fatalf("SaveCache (second): %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat (second): %v", err)
	}
	if os.SameFile(before, after) {
		t.Error("the second snapshot went into the file the first one created; a client reading it mid-write gets a truncated cache and falls back to a network bootstrap it may not be able to make")
	}
	got, err := LoadCache(path)
	if err != nil {
		t.Fatalf("LoadCache: %v", err)
	}
	if string(got) != "second opaque signed snapshot, a different length" {
		t.Errorf("LoadCache = %q, want the second snapshot whole", got)
	}
	assertNoStagedFiles(t, dir, path, "after a cache save that completed")
}

// TestSaveFileDoesNotCreateParentDirectories pins a deliberate NON-change.
//
// Three of this repository's atomic writers mkdir their parent and three do not,
// and this one is in the second group on purpose: the secrets file's default
// path is the coordinator's own -bootstrap-secrets directory, and a mint that
// silently conjures a fresh secrets/ somewhere else is how an operator ends up
// issuing invites against a file no coordinator is reading. The old os.WriteFile
// failed here too; a helper that quietly started succeeding would be a
// behavioural change nobody asked for.
func TestSaveFileDoesNotCreateParentDirectories(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir", "bootstrap-secrets.json")
	if err := synthStore("issued", 1).SaveFile(missing); err == nil {
		t.Fatal("SaveFile into a missing directory succeeded; it must fail exactly as the os.WriteFile it replaced did")
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Errorf("SaveFile created %s; it must not", filepath.Dir(missing))
	}
}

// TestSaveFileInstallsMode0600OverAWiderFile pins the first of the three
// consequences [writeFileAtomic] names.
//
// os.WriteFile applied its perm only when CREATING, so a secrets file that had
// somehow become group- or world-readable kept that mode through every
// subsequent mint. Installing a fresh file installs this one's mode instead,
// which only ever narrows — and this file holds every user's HMAC key.
func TestSaveFileInstallsMode0600OverAWiderFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not carry Unix permission bits, so there is nothing here to assert")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap-secrets.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed a wide file: %v", err)
	}
	if err := synthStore("issued", 1).SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("secrets file mode = %04o after a save, want 0600; every user's HMAC key is in it", got)
	}
}

// TestAConcurrentReloadNeverSeesAPartialSecretsFile models what cmd/coordinator
// actually does: reloadSecretsLoop re-reads this path on its own timer, in
// another process, with no coordination with whatever is writing it.
//
// Every read must therefore land on a WHOLE generation. The two generations
// differ by three orders of magnitude in length so a torn write has something to
// be torn between, and both ends of each are probed rather than one, so a file
// that was somehow short at the tail is caught rather than mistaken for the
// generation it started as.
//
// Note which direction the failure would take. A reload that reads a truncated
// file is the fail-CLOSED half here — startTurnAndBootstrap seeds an empty store
// and the loop keeps its previous one on a parse error, so the worst outcome is
// that nobody can bootstrap, loudly. This test is not where the danger is. It is
// here because it is the cheap, continuous sampler: it looks at the file
// thousands of times while it is being rewritten, which is the only way to
// observe that there is no window at all.
func TestAConcurrentReloadNeverSeesAPartialSecretsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap-secrets.json")

	// Three orders of magnitude apart is the property; the exact sizes are not.
	// Both are far larger than the window matters for — see the killed-writer
	// test below on why a big file is the WEAKER discriminator, not the stronger
	// one — so these are sized for a fast test rather than for sensitivity.
	const (
		smallN = 4
		largeN = 3000
	)
	small := synthStore("small", smallN)
	large := synthStore("large", largeN)
	if err := small.SaveFile(path); err != nil {
		t.Fatalf("SaveFile (seed): %v", err)
	}

	type result struct {
		reads int
		err   error
	}
	stop := make(chan struct{})
	done := make(chan result, 1)
	go func() {
		var r result
		for {
			select {
			case <-stop:
				done <- r
				return
			default:
			}
			store, err := LoadMemStore(path)
			if err != nil {
				r.err = fmt.Errorf("a reload read a secrets file it could not parse after %d whole ones; the coordinator keeps its previous store and NOBODY can bootstrap until the next tick repairs it: %w", r.reads, err)
				done <- r
				return
			}
			has := func(id string) bool { _, ok := store.Lookup(id); return ok }
			isSmall := has("small-0000") && has(fmt.Sprintf("small-%04d", smallN-1)) && !has("large-0000")
			isLarge := has("large-0000") && has(fmt.Sprintf("large-%04d", largeN-1)) && !has("small-0000")
			if !isSmall && !isLarge {
				r.err = fmt.Errorf("a reload read a secrets file of %d entries that is neither generation whole; it caught a write in progress", len(storeIDs(store)))
				done <- r
				return
			}
			r.reads++
		}
	}()

	const rounds = 40
	for i := 0; i < rounds; i++ {
		gen := small
		if i%2 == 1 {
			gen = large
		}
		if err := gen.SaveFile(path); err != nil {
			close(stop)
			<-done
			t.Fatalf("SaveFile round %d: %v", i, err)
		}
	}
	close(stop)

	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.reads == 0 {
		t.Fatal("the reader completed no reads at all, so this test asserted nothing")
	}
	t.Logf("%d reloads across %d writes, every one a whole generation", got.reads, rounds)
	assertNoStagedFiles(t, dir, path, "after 40 saves that completed")
}

// killTargetEnv names the file the child half of
// TestAKilledIssuerLeavesTheSecretsFileWhole saves to. Its presence is also what
// tells that test it IS the child, the same re-exec shape core/admission's
// SaveFile tests and cmd/bacchus-netd's namespace tests use.
const killTargetEnv = "BACCHUS_COLDSTART_SAVEFILE_KILL_TARGET"

// childReady is printed by the child once it is looping, so the parent kills a
// process that is mid-save rather than one still starting up.
const childReady = "saving"

// killGenA and killGenB are the two whole generations the child alternates
// between. Anything else on disk after a kill is a torn write.
const (
	killGenA = 3
	killGenB = 7
)

// TestAKilledIssuerLeavesTheSecretsFileWhole is the failure issue #178 is
// actually about.
//
// Not a reader that catches a bad moment — that one is fail-closed and the next
// tick repairs it — but a WRITER that dies in one and leaves the bad moment on
// disk. cmd/coldstart-issue loads the whole store, adds one secret and writes
// all of it back, so the file it leaves truncated is not missing an update: it
// is missing every bootstrap secret ever issued, each of which exists nowhere
// else except in an invite already handed to somebody.
//
// A child process saves in a tight loop and is killed at a series of jittered
// moments. However it dies, the file must parse and must hold one of the two
// generations whole.
//
// SMALL STORES ON PURPOSE, which is the opposite of the intuition and the thing
// most likely to be "improved" later. The window os.WriteFile exposes is between
// open(O_TRUNC) and the first byte, and it does not grow with the file: a large
// store lengthens the marshal and the write, which are the parts that were
// already safe, and so shrinks the share of each cycle spent in the state this
// is hunting for. Small stores spend a large fraction of every cycle there.
//
// RE-EXEC RATHER THAN A GOROUTINE, for the same reason the defect exists at all:
// a goroutine cannot be stopped between two syscalls, and what is being asserted
// is what survives a process that stopped without unwinding.
func TestAKilledIssuerLeavesTheSecretsFileWhole(t *testing.T) {
	if target := os.Getenv(killTargetEnv); target != "" {
		saveUntilKilled(target)
		return
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap-secrets.json")

	const attempts = 12
	for i := 0; i < attempts; i++ {
		cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1")
		cmd.Env = append(os.Environ(), killTargetEnv+"="+path)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatalf("attempt %d: stdout pipe: %v", i, err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatalf("attempt %d: start the writer: %v", i, err)
		}
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != childReady {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("attempt %d: the writer never reported it was saving (read %q, %v)", i, line, err)
		}
		// Jittered so the kills sweep across the save cycle rather than landing
		// on one phase of it. Any offset works — the child is saving
		// continuously by this point — and the sweep is what makes "including
		// near the end of a write" fall out rather than be aimed at.
		time.Sleep(time.Duration(300+i*211) * time.Microsecond)
		// The error is ignored: a child that has already exited on its own
		// deadline is not a failure of this test, and the file it left is
		// asserted either way.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		store, err := LoadMemStore(path)
		if err != nil {
			t.Fatalf(`attempt %d: the issuer was killed and left a secrets file that does not parse: %v

This is the loss issue #178 exists to prevent. cmd/coldstart-issue is
read-modify-write, so what is gone is not one entry but every bootstrap secret
ever issued — random values that live only in this file and in bacchus1: invites
already in other people's hands.`, i, err)
		}
		if n := len(storeIDs(store)); n != killGenA && n != killGenB {
			t.Fatalf("attempt %d: the killed issuer left %d secrets; the only whole generations are %d and %d, so this file was caught mid-write", i, n, killGenA, killGenB)
		}
	}

	// Debris is EXPECTED here and is not what is being asserted: a process
	// killed between staging and rename cannot clean up after itself. What is
	// asserted is that it can never be confused with the secrets file — the
	// staged name carries the target's name, a .tmp marker and a leading dot.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	base := filepath.Base(path)
	for _, e := range entries {
		if e.Name() == base {
			continue
		}
		if !strings.HasPrefix(e.Name(), "."+base+".tmp") {
			t.Errorf("a killed save left %q beside the secrets file; a staged file must be named so nothing can mistake it for the file itself", e.Name())
		}
	}
}

// saveUntilKilled is the child half of the test above. It saves alternating
// generations until the parent kills it, and returns on its own deadline only so
// that a parent which somehow fails to kill it cannot leave a process behind.
func saveUntilKilled(path string) {
	gens := [2]*MemStore{synthStore("gen-a", killGenA), synthStore("gen-b", killGenB)}
	if err := gens[0].SaveFile(path); err != nil {
		fmt.Println("save failed:", err)
		return
	}
	fmt.Println(childReady)
	deadline := time.Now().Add(20 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		if err := gens[i%2].SaveFile(path); err != nil {
			fmt.Println("save failed:", err)
			return
		}
	}
}

// assertNoStagedFiles checks a completed save cleaned up after itself. A staged
// file left in the coordinator's secrets directory by a save that SUCCEEDED is a
// leak, not a crash artifact, and it would accumulate one per issued invite —
// each one a complete copy of every secret.
func assertNoStagedFiles(t *testing.T, dir, path, when string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	prefix := "." + filepath.Base(path) + ".tmp"
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			t.Errorf("%s: %q was left behind; a save that completes must remove or rename away everything it staged", when, e.Name())
		}
	}
}
