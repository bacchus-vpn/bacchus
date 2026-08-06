// The installer's AppMutex against this package's mutex names (bacchus#185).
//
// One named mutex settles both halves of #185 — a second client refusing to
// arm, and an installer that notices a running one — but only if the name is
// identical in both places. Nothing else in this repository would notice a
// drift:
//
//   - The .iss is not Go. `go build`, `go vet` and every other test in the tree
//     are blind to it.
//   - Inno compiles an AppMutex naming a mutex nobody ever creates perfectly
//     cleanly. release.yml's windows-bundle job would go green.
//   - The failure is silent AT RUNTIME too. An installer that finds no mutex
//     behaves exactly like one running on a machine with no client open: it
//     proceeds. The only way to see it otherwise is to run an uninstall over a
//     running client on real hardware and notice that it did not stop — which
//     is how #185 was found in the first place, and is not a check that runs on
//     a pull request.
//
// So the two are compared here, in a test that needs no Windows and no Inno
// Setup, in the manifest_test.go / i18n_test.go shape: a Go test that reads a
// non-Go build artifact.
//
// It lives in THIS package rather than beside the script in deploy/windows
// because Go's internal rule puts clients/fyne/internal out of that package's
// reach, and the alternative — hoisting the names somewhere importable — would
// move a constant out of the package that owns it to satisfy a test.
package singleinstance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// issScriptPath is the Inno Setup script, reached from this package's
// directory. Four levels up is the repository root: singleinstance -> internal
// -> fyne -> clients.
var issScriptPath = filepath.Join("..", "..", "..", "..", "deploy", "windows", "bacchus.iss")

// setupDirective returns the value of a [Setup] directive from the script, and
// whether it was found. Directives are `Name=value` on their own line;
// semicolon-prefixed lines are comments and are skipped, which matters here
// because the comment block above AppMutex names the same strings and would
// otherwise match.
func setupDirective(t *testing.T, name string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(issScriptPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", issScriptPath, err)
	}
	prefix := name + "="
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix)), true
		}
	}
	return "", false
}

// TestAppMutexNamesTheClientsMutexes is the drift guard itself.
//
// Mutation check: rename either constant above, or edit either name in the
// .iss, and this names the exact string that no longer has a counterpart.
func TestAppMutexNamesTheClientsMutexes(t *testing.T) {
	value, ok := setupDirective(t, "AppMutex")
	if !ok {
		t.Fatal("bacchus.iss declares no AppMutex — the uninstaller will run straight through a running client (bacchus#185)")
	}

	declared := map[string]bool{}
	for _, n := range strings.Split(value, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			t.Errorf("AppMutex=%q has an empty entry, which matches nothing", value)
			continue
		}
		declared[n] = true
	}

	for _, want := range []string{GlobalMutexName, SessionMutexName} {
		if !declared[want] {
			t.Errorf("AppMutex=%q does not name %q, which the client creates — the installer will not see a running client holding only that one", value, want)
		}
		delete(declared, want)
	}
	for extra := range declared {
		// An extra name is not harmless: Setup refuses while ANY listed mutex
		// exists, so a stray name is a way for an unrelated program to block
		// every Bacchus install on the machine.
		t.Errorf("AppMutex names %q, which nothing in this repository creates", extra)
	}
}

// TestRestartManagerIsOff guards the ruling that goes with the mutex.
//
// Inno's default is CloseApplications=yes, and its fallback for an application
// that will not close gracefully is to terminate it. Since bacchus#186 this
// client HIDES on a window-close message rather than exiting, so the graceful
// path always fails and the fallback always fires — and a terminated Bacchus is
// bacchus#115's stranded machine, kill-switch still armed with nothing left to
// lift it. The refusal has to come from AppMutex, which sends the user through
// the client's own Quit.
func TestRestartManagerIsOff(t *testing.T) {
	value, ok := setupDirective(t, "CloseApplications")
	if !ok {
		t.Fatal("bacchus.iss does not set CloseApplications, so it defaults to yes and the Restart Manager may terminate a running client (bacchus#115)")
	}
	if !strings.EqualFold(value, "no") {
		t.Errorf("CloseApplications=%q, want no — see this test's doc", value)
	}
}
