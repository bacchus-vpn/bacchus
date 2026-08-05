package admission

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// base is a fixed clock so the validity-window cases are deterministic: every
// credential window and the now passed to Verify are expressed relative to it.
var base = time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

func TestVerifyPolicy(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	cases := []struct {
		name     string
		roles    []Role
		subject  string    // credential's Subject
		nbf, exp time.Time // credential window
		revoke   bool      // revoke the credential's serial before verifying

		want     Role   // role the peer is taking now
		vSubject string // subject passed to Verify ("" == client/no binding)
		wantErr  error  // nil == admit
	}{
		{
			name:  "valid exit node, subject bound",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "exit-A", wantErr: nil,
		},
		{
			name:  "valid client, no subject binding",
			roles: []Role{RoleClient}, subject: "user-7", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleClient, vSubject: "", wantErr: nil,
		},
		{
			name:  "multi-role credential used for one of its roles",
			roles: []Role{RoleRelay, RoleExit}, subject: "node-M", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleRelay, vSubject: "node-M", wantErr: nil,
		},
		{
			name:  "expired",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(-2 * time.Hour), exp: base.Add(-time.Hour),
			want: RoleExit, vSubject: "exit-A", wantErr: ErrExpired,
		},
		{
			name:  "not yet valid beyond skew",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(10 * time.Minute), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "exit-A", wantErr: ErrNotYetValid,
		},
		{
			name:  "not yet valid but within clock skew is admitted",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(time.Minute), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "exit-A", wantErr: nil,
		},
		{
			name:  "role not authorized",
			roles: []Role{RoleClient}, subject: "user-7", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "user-7", wantErr: ErrRoleNotAuthorized,
		},
		{
			name:  "subject mismatch (credential replayed by another node)",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			want: RoleExit, vSubject: "exit-B", wantErr: ErrSubjectMismatch,
		},
		{
			name:  "revoked",
			roles: []Role{RoleExit}, subject: "exit-A", nbf: base.Add(-time.Hour), exp: base.Add(time.Hour),
			revoke: true,
			want:   RoleExit, vSubject: "exit-A", wantErr: ErrRevoked,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, enc, err := Issue(priv, tc.subject, tc.roles, tc.nbf, tc.exp, "")
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			rl := NewRevocationList()
			if tc.revoke {
				rl.Revoke(c.Serial)
			}
			v := NewVerifier(pub, rl.Revoked)

			got, err := v.Verify(enc, base, tc.want, tc.vSubject)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify err = %v, want admit", err)
				}
				if got.Serial != c.Serial {
					t.Fatalf("admitted credential serial = %q, want %q", got.Serial, c.Serial)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// A verifier with no revocation oracle (nil) must treat nothing as revoked.
func TestNewVerifierNilRevokedIsSafe(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, enc, err := Issue(priv, "exit-A", []Role{RoleExit}, base.Add(-time.Hour), base.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v := NewVerifier(pub, nil)
	if _, err := v.Verify(enc, base, RoleExit, "exit-A"); err != nil {
		t.Fatalf("Verify with nil revoked oracle err = %v, want admit", err)
	}
}

func TestRevocationListRoundTrip(t *testing.T) {
	rl := NewRevocationList()
	rl.Revoke("cafe")
	rl.Revoke("babe")
	if !rl.Revoked("cafe") || !rl.Revoked("babe") {
		t.Fatal("Revoke did not record serials")
	}
	if rl.Revoked("f00d") {
		t.Fatal("unrevoked serial reported revoked")
	}

	path := filepath.Join(t.TempDir(), "revocations.json")
	if err := rl.SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	loaded, err := LoadRevocationList(path)
	if err != nil {
		t.Fatalf("LoadRevocationList: %v", err)
	}
	if !loaded.Revoked("cafe") || !loaded.Revoked("babe") || loaded.Revoked("f00d") {
		t.Fatal("loaded revocation list does not match saved")
	}
}

func TestLoadRevocationListMissingFileIsErrNotExist(t *testing.T) {
	_, err := LoadRevocationList(filepath.Join(t.TempDir(), "nope.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadRevocationList(missing) err = %v, want wrapped os.ErrNotExist", err)
	}
}

// TestRevocationListSerialsSorted: Serials returns every revoked serial in a
// stable sorted order regardless of insertion order — cmd/admission-issue -crl
// (issue #69) signs exactly this slice, so its output must be deterministic.
func TestRevocationListSerialsSorted(t *testing.T) {
	rl := NewRevocationList()
	if got := rl.Serials(); len(got) != 0 {
		t.Fatalf("empty list Serials() = %v, want empty", got)
	}
	rl.Revoke("cafe")
	rl.Revoke("babe")
	rl.Revoke("dead")
	got := rl.Serials()
	want := []string{"babe", "cafe", "dead"}
	if len(got) != len(want) {
		t.Fatalf("Serials() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Serials() = %v, want %v", got, want)
		}
	}
}

// The three tests below are issue #168: SaveFile must install a whole file
// rather than truncate and refill the one cmd/coordinator is reading.
//
// They come at it from the three angles that are actually distinct, because no
// one of them covers the others:
//
//   - what the implementation DID (it replaced the file rather than rewriting
//     it) — deterministic, and the assertion that fails the moment this becomes
//     an os.WriteFile again;
//   - what a concurrent RELOADER can observe while a save is in flight;
//   - what a killed WRITER leaves on disk, which is the failure the card is
//     about: not a bad moment somebody reads, but a bad moment left lying
//     around for the next coordinator restart to find.

// TestSaveFileReplacesTheFileRatherThanRewritingIt is the assertion that tells
// the two implementations apart, and it is about the INODE rather than the
// bytes.
//
// os.WriteFile — what this used to be — opens the live file with O_TRUNC and
// refills it, so between the truncate and the last byte a reload can read a
// shorter list or an empty one, and a shorter revocation list admits more. A
// rename installs a file that was already complete before it had a name anybody
// reads, so no such moment exists.
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
	path := filepath.Join(dir, "admission-revocations.json")

	first := NewRevocationList()
	first.Revoke("cafe")
	if err := first.SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	witness := filepath.Join(dir, "witness.json")
	linked := os.Link(path, witness) == nil

	second := NewRevocationList()
	second.Revoke("cafe")
	second.Revoke("babe")
	if err := second.SaveFile(path); err != nil {
		t.Fatalf("SaveFile (second): %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat (second): %v", err)
	}
	if os.SameFile(before, after) {
		t.Error("the second list went into the same file the first save created; a truncate-and-write is readable as a shorter revocation list, and a shorter one admits more")
	}
	if linked {
		old, err := LoadRevocationList(witness)
		if err != nil {
			t.Fatalf("the file the first save created no longer parses, so the second save wrote through it: %v", err)
		}
		if old.Revoked("babe") {
			t.Error("the second list was written INTO the file the first save created, so anything already reading that file saw it change underneath")
		}
	}

	loaded, err := LoadRevocationList(path)
	if err != nil {
		t.Fatalf("LoadRevocationList: %v", err)
	}
	if !loaded.Revoked("cafe") || !loaded.Revoked("babe") {
		t.Errorf("installed list = %v, want both serials", loaded.Serials())
	}
	assertNoStagedFiles(t, dir, path, "after a save that completed")
}

// TestAConcurrentReloadNeverSeesAPartialList models what cmd/coordinator
// actually does: reloadRevocationsLoop re-reads this path on its own timer, in
// another process, with no coordination with whatever is writing it.
//
// Every read must therefore land on a WHOLE generation. The two generations
// differ by three orders of magnitude in length so a torn write has something to
// be torn between, and both ends of each are probed rather than one, so a list
// that was somehow short at the tail is caught rather than mistaken for the
// generation it started as.
//
// Note which direction the failure would take. A reload that reads a truncated
// file is the FAIL-SAFE half — the loop keeps its previous in-memory list — so
// this test is not where the danger is. It is here because it is the cheap,
// continuous sampler: it looks at the file thousands of times while it is being
// rewritten, which is the only way to observe that there is no window at all.
func TestAConcurrentReloadNeverSeesAPartialList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admission-revocations.json")

	const (
		smallN = 4
		largeN = 10000
	)
	small := NewRevocationList()
	for i := 0; i < smallN; i++ {
		small.Revoke(fmt.Sprintf("small-%04d", i))
	}
	large := NewRevocationList()
	for i := 0; i < largeN; i++ {
		large.Revoke(fmt.Sprintf("large-%06d", i))
	}
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
			rl, err := LoadRevocationList(path)
			if err != nil {
				r.err = fmt.Errorf("a reload read a file it could not parse after %d whole ones; at coordinator STARTUP that is read as nothing being revoked: %w", r.reads, err)
				done <- r
				return
			}
			isSmall := rl.Revoked("small-0000") && rl.Revoked(fmt.Sprintf("small-%04d", smallN-1)) && !rl.Revoked("large-000000")
			isLarge := rl.Revoked("large-000000") && rl.Revoked(fmt.Sprintf("large-%06d", largeN-1)) && !rl.Revoked("small-0000")
			if !isSmall && !isLarge {
				r.err = fmt.Errorf("a reload read a list of %d serials that is neither generation whole; it caught a write in progress", len(rl.Serials()))
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
// TestAKilledWriterLeavesTheListWhole saves to. Its presence is also what tells
// that test it IS the child, the same re-exec shape cmd/bacchus-netd's namespace
// tests use.
const killTargetEnv = "BACCHUS_ADMISSION_SAVEFILE_KILL_TARGET"

// childReady is printed by the child once it is looping, so the parent kills a
// process that is mid-save rather than one still starting up.
const childReady = "saving"

// killGenA and killGenB are the two whole generations the child alternates
// between. Anything else on disk after a kill is a torn write.
const (
	killGenA = 3
	killGenB = 7
)

// TestAKilledWriterLeavesTheListWhole is the failure issue #168 is actually
// about. Not a reader that catches a bad moment — that one is fail-safe, since
// the reload loop keeps its previous list — but a WRITER that dies in one and
// leaves the bad moment on disk, where the next coordinator restart finds it
// hours or weeks later with nothing connecting it to the revocation that caused
// it. At startup there is no previous list and -admission-revocations says an
// unparseable file means nothing is revoked.
//
// A child process saves in a tight loop and is killed at a series of jittered
// moments. However it dies, the file must parse and must hold one of the two
// generations whole.
//
// SMALL LISTS ON PURPOSE, which is the opposite of the intuition. The window
// os.WriteFile exposes is between the truncate and the first byte and does not
// grow with the file: a large list lengthens the marshal and the write, which
// are the parts that were already safe, and so shrinks the share of each cycle
// spent in the state this is hunting for. Small lists spend a large fraction of
// every cycle there.
//
// RE-EXEC RATHER THAN A GOROUTINE, for the same reason the defect exists at all:
// a goroutine cannot be stopped between two syscalls, and what is being asserted
// is what survives a process that stopped without unwinding.
func TestAKilledWriterLeavesTheListWhole(t *testing.T) {
	if target := os.Getenv(killTargetEnv); target != "" {
		saveUntilKilled(target)
		return
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "admission-revocations.json")

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
		// Jittered so the kills sweep across the save cycle rather than
		// landing on one phase of it. Any offset works — the child is
		// saving continuously by this point — and the sweep is what makes
		// "including near the end of a write" fall out rather than be aimed at.
		time.Sleep(time.Duration(300+i*211) * time.Microsecond)
		// The error is ignored: a child that has already exited on its own
		// deadline is not a failure of this test, and the file it left is
		// asserted either way.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		rl, err := LoadRevocationList(path)
		if err != nil {
			t.Fatalf(`attempt %d: the writer was killed and left a revocation file that does not parse: %v

This is the delayed failure the atomic write exists to prevent. A running
coordinator keeps its previous list and survives it; the next RESTART has no
previous list, and -admission-revocations says a missing or unparseable file
means nothing is revoked.`, i, err)
		}
		if n := len(rl.Serials()); n != killGenA && n != killGenB {
			t.Fatalf("attempt %d: the killed writer left %d serials; the only whole generations are %d and %d, so this file was caught mid-write", i, n, killGenA, killGenB)
		}
	}

	// Debris is EXPECTED here and is not what is being asserted: a process
	// killed between staging and rename cannot clean up after itself. What is
	// asserted is that it can never be confused with the list — the staged name
	// carries the target's name, a .tmp marker and a leading dot.
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
			t.Errorf("a killed save left %q beside the list; a staged file must be named so nothing can mistake it for the list itself", e.Name())
		}
	}
}

// saveUntilKilled is the child half of the test above. It saves alternating
// generations until the parent kills it, and returns on its own deadline only so
// that a parent which somehow fails to kill it cannot leave a process behind.
func saveUntilKilled(path string) {
	gens := [2]*RevocationList{NewRevocationList(), NewRevocationList()}
	for i := 0; i < killGenA; i++ {
		gens[0].Revoke(fmt.Sprintf("gen-a-%02d", i))
	}
	for i := 0; i < killGenB; i++ {
		gens[1].Revoke(fmt.Sprintf("gen-b-%02d", i))
	}
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
// leak, not a crash artifact, and it would accumulate one per revocation.
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
