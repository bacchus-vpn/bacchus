// The contract deploy/bacchus-node-id.sh reads is a LOG LINE, written in Go and parsed
// in shell — the pair that drifts silently, and the same hazard ADR-0069 §4 names about
// the update marker. So this test does what deploy/update_rollback_test.go does with
// update.Apply: it never hand-writes the input. It builds cmd/node, runs it, and feeds
// the bytes the real binary actually produced through the real script.
//
// It also stands as the evidence for a correction to issue #232. That card was filed
// reading that "cmd/node logs nothing at startup that names the id", and concluded that
// a box therefore cannot be asked what it registers as, even over ssh. What is true is
// that core/engine.go's ID() method is never called. The id itself has been in every
// node's journal all along: core.Engine.Start emits
//
//	exit <id> (<country>) advertising <host:port> + direct WebRTC
//	relay <id> online
//
// through e.emit, and e.emit falls back to log.Println whenever Config.OnEvent is nil.
// clients/fyne sets OnEvent; cmd/node does not, so on a node box those lines go to
// stderr and systemd files them in the journal. Nothing in cmd/ or core/ had to change
// for the pairing issue #232 asks for — which is fortunate, because core/engine.go was
// frozen for the wave that closed it. What had to change is that the line is now
// LOAD-BEARING, and this is what says so to whoever next rewords it.
package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A 32-byte X25519 private key, fixed so the run is deterministic. Test material: it
// is in a public repository, which is exactly why it must never be a real EXIT_KEY.
const testExitKeyHex = "4141414141414141414141414141414141414141414141414141414141414141"

// runNodeBriefly starts the real binary, waits for it to say something, and kills it.
// It never reaches a coordinator: 127.0.0.1:1 refuses, which the node logs and carries
// on from, and that is the whole point — a box states its identity before it has spoken
// to anybody, which is what makes it answerable over ssh when the coordinator is
// precisely what it cannot reach.
func runNodeBriefly(t *testing.T, bin string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	logPath := filepath.Join(t.TempDir(), "node.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the node: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Poll rather than sleep a fixed amount: the lines appear in milliseconds on a
	// quiet machine and this has to survive a loaded CI runner too.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(logPath)
		if err == nil && (strings.Contains(string(b), " online") || strings.Contains(string(b), "direct WebRTC")) {
			return string(b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("the node printed no startup line naming its id within the deadline. It printed:\n%s", b)
	return ""
}

func TestTheNodeStartupLineCarriesTheIdThisScriptReads(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs cmd/node")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}

	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "bacchus-node")
	build := exec.Command("go", "build", "-o", bin, "./cmd/node")
	build.Dir = root
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building cmd/node: %v\n%s", err, b)
	}

	// A relay names the id it was GIVEN, which closes the loop on what the script
	// recovers: -id sets core.Config.ID, and core/engine.go's registerLoop puts that
	// same field on the register wire the coordinator prints as `<role> registered:
	// <id>`. So an id read off this line is the id the pin will look for in the
	// coordinator's journal — which is the only property the roll call needs.
	t.Run("relay", func(t *testing.T) {
		const want = "a9beefcafe01"
		out := runNodeBriefly(t, bin,
			"-role", "relay", "-id", want, "-coordinators", "127.0.0.1:1")
		got, code := nodeID(t, out)
		if code != 0 {
			t.Fatalf("bacchus-node-id.sh exit %d on the real binary's output:\n%s\n--- node said ---\n%s", code, got, out)
		}
		if strings.TrimSpace(got) != want {
			t.Errorf("read %q, want %q — the id on the wire and the id in the log have parted company\n--- node said ---\n%s",
				strings.TrimSpace(got), want, out)
		}
	})

	// An exit does not take its id from a flag: it IS the X25519 public key derived
	// from -exit-key, which is why the two namespaces could not be joined by reading
	// configuration. The derivation is core's and is not repeated here — what is
	// asserted is that the script recovers whatever the binary chose, and that the
	// shape is the 64 hex characters a public key is, since that is the claim the pin
	// and issue #232 both rest on.
	t.Run("exit", func(t *testing.T) {
		out := runNodeBriefly(t, bin,
			"-role", "exit",
			"-listen", "127.0.0.1:0",
			"-advertise", "192.0.2.10:20000",
			"-country", "NL",
			"-exit-key", testExitKeyHex,
			"-coordinators", "127.0.0.1:1")
		got, code := nodeID(t, out)
		if code != 0 {
			t.Fatalf("bacchus-node-id.sh exit %d on the real binary's output:\n%s\n--- node said ---\n%s", code, got, out)
		}
		id := strings.TrimSpace(got)
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(id) {
			t.Fatalf("read %q, want 64 hex characters (an exit id IS its X25519 public key)\n--- node said ---\n%s", id, out)
		}
		if !strings.Contains(out, id) {
			t.Errorf("the script invented %q; it is not in what the node printed:\n%s", id, out)
		}
		// The same run, twice: an exit's identity comes from the key and must not move.
		again := runNodeBriefly(t, bin,
			"-role", "exit",
			"-listen", "127.0.0.1:0",
			"-advertise", "192.0.2.10:20000",
			"-country", "NL",
			"-exit-key", testExitKeyHex,
			"-coordinators", "127.0.0.1:1")
		got2, _ := nodeID(t, again)
		if strings.TrimSpace(got2) != id {
			t.Errorf("two starts with one -exit-key produced %q then %q, so a roll call could never match a box twice",
				id, strings.TrimSpace(got2))
		}
	})
}
