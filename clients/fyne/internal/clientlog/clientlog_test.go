package clientlog

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

// readFile is a t.Fatal-ing os.ReadFile, since almost every check here is
// "what is on the disk now".
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return string(b)
}

// TestDefaultDirMatchesTheConfigDirectory is the drift guard named in
// DefaultDir's doc. This package derives <UserConfigDir>/Bacchus independently
// of appstate, and the two must stay the same directory: the Windows
// uninstaller offers to remove {userappdata}\Bacchus and nothing else, so a log
// written one directory over would be residue that survives an uninstall — for
// a product whose users uninstall it precisely to leave nothing behind.
//
// Mutation check: change either component of DefaultDir's Join and this names
// the mismatch.
func TestDefaultDirMatchesTheConfigDirectory(t *testing.T) {
	credDir := appstate.DefaultDeviceCredDir()
	if credDir == "" {
		t.Skip("no per-user config directory on this system")
	}
	want := filepath.Dir(credDir)
	if got := DefaultDir(); got != want {
		t.Errorf("DefaultDir() = %q, want %q (the directory appstate keeps the config and device identity in)", got, want)
	}
}

// TestWritesAndRedacts covers the sink's whole reason to exist: a line reaches
// the disk, and it reaches it redacted.
func TestWritesAndRedacts(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, Options{Redact: func(in string) string {
		return strings.ReplaceAll(in, "203.0.113.7", "<ip>")
	}})
	t.Cleanup(func() { _ = s.Close() })

	if !s.Enabled() {
		t.Fatal("a fresh directory should log by default — that is the D2 ruling")
	}
	if _, err := s.Write([]byte("dial 203.0.113.7:7000 failed\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readFile(t, filepath.Join(dir, FileName))
	if strings.Contains(got, "203.0.113.7") {
		t.Errorf("the coordinator address reached the disk: %q", got)
	}
	if !strings.Contains(got, "<ip>:7000") {
		t.Errorf("redacted line missing from %q", got)
	}
}

// TestRedactsTheHomeDirectory guards the bar this package adds on top of the
// injected redactor. Paths carry the local account name on both 1.0 platforms
// and every writer can emit one, because Go's os errors quote the path.
func TestRedactsTheHomeDirectory(t *testing.T) {
	if homeDir == "" {
		t.Skip("no home directory on this system")
	}
	dir := t.TempDir()
	s := New(dir, Options{})
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Write([]byte("config: open " + homeDir + "/.config/Bacchus/fyne-client.json: permission denied\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readFile(t, filepath.Join(dir, FileName))
	if strings.Contains(got, homeDir) {
		t.Errorf("the home directory reached the disk: %q", got)
	}
	if !strings.Contains(got, "~/.config/Bacchus/fyne-client.json") {
		t.Errorf("want the path with ~ substituted, got %q", got)
	}
}

// TestRotationCapsWhatIsOnDisk is the "recent history, not a diary" property.
// D2 answers the forensic-footprint cost with a cap; a cap nothing enforces is
// the same file with a comment on it.
func TestRotationCapsWhatIsOnDisk(t *testing.T) {
	dir := t.TempDir()
	const max = 512
	s := New(dir, Options{MaxBytes: max})
	t.Cleanup(func() { _ = s.Close() })

	line := strings.Repeat("x", 99) + "\n"
	for i := 0; i < 40; i++ {
		if _, err := s.Write([]byte(line)); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	live, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("stat live log: %v", err)
	}
	if live.Size() > max {
		t.Errorf("live log is %d bytes, over the %d cap", live.Size(), max)
	}
	rotated, err := os.Stat(filepath.Join(dir, RotatedFileName))
	if err != nil {
		t.Fatalf("stat rotated log: %v", err)
	}
	if rotated.Size() > max {
		t.Errorf("rotated log is %d bytes, over the %d cap", rotated.Size(), max)
	}

	// Exactly two generations, ever. A third would mean rotation is
	// accumulating rather than replacing, which is the diary this cap exists to
	// prevent.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("log directory holds %v, want exactly %s and %s", names, FileName, RotatedFileName)
	}

	// The newest line has to be in the LIVE file, or rotation has thrown away
	// the half a support request is about.
	if !strings.Contains(readFile(t, filepath.Join(dir, FileName)), "x") {
		t.Error("the live log is empty after rotation")
	}
}

// TestOffDeletesAndStaysOff is D2's off-switch: it turns the log off, it
// removes what is already there, and the decision survives a restart.
func TestOffDeletesAndStaysOff(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, Options{MaxBytes: 64})
	for i := 0; i < 8; i++ {
		if _, err := s.Write([]byte("a line that is long enough to force a rotation\n")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, RotatedFileName)); err != nil {
		t.Fatalf("wanted a rotated file to exist before the delete: %v", err)
	}

	if err := s.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if s.Enabled() {
		t.Error("Enabled() is still true after being switched off")
	}
	// BOTH generations. Deleting only the live file would leave the older half
	// of the same record on the disk, which is the whole thing the user asked
	// to be rid of.
	for _, name := range []string{FileName, RotatedFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still exists after SetEnabled(false) (err=%v)", name, err)
		}
	}
	// A write afterwards must not resurrect it.
	if _, err := s.Write([]byte("after the switch\n")); err != nil {
		t.Fatalf("Write after off: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Error("writing after SetEnabled(false) recreated the log file")
	}

	// A fresh Sink over the same directory — the next launch — must find the
	// switch still off. This is the property a marker file has and an in-memory
	// flag does not.
	next := New(dir, Options{})
	t.Cleanup(func() { _ = next.Close() })
	if next.Enabled() {
		t.Error("a new Sink over a directory with the marker in it started logging again")
	}
	if next.Path() != filepath.Join(dir, FileName) {
		t.Errorf("Path() = %q, want the log path even while off — the UI shows where it WOULD be", next.Path())
	}
}

// TestBackOnStartsAFreshFile is the other half of the switch.
func TestBackOnStartsAFreshFile(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, Options{})
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Write([]byte("before\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if err := s.SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if !s.Enabled() {
		t.Fatal("Enabled() is false after being switched back on")
	}
	if _, err := os.Stat(filepath.Join(dir, DisabledMarkerName)); !errors.Is(err, os.ErrNotExist) {
		t.Error("the marker file survived SetEnabled(true)")
	}
	if _, err := s.Write([]byte("after\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readFile(t, filepath.Join(dir, FileName))
	if strings.Contains(got, "before") {
		t.Errorf("the deleted log came back: %q", got)
	}
	if !strings.Contains(got, "after") {
		t.Errorf("the new log is missing the line written after it was re-enabled: %q", got)
	}
}

// TestEchoSurvivesEveryState covers Options.Echo's contract: it is what a
// developer running the binary from a shell sees, and it is deliberately not
// gated on the file. It is also the only surface left when the file cannot be
// opened at all, which is the failure this sink must not turn into an outage.
func TestEchoSurvivesEveryState(t *testing.T) {
	dir := t.TempDir()
	var echo bytes.Buffer
	s := New(dir, Options{Echo: &echo})
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Write([]byte("one\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if _, err := s.Write([]byte("two\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := echo.String(); got != "one\ntwo\n" {
		t.Errorf("echo = %q, want both lines — the file being off must not silence stderr", got)
	}
}

// TestNoDirectoryIsNotAnError is the machine that cannot name a per-user
// directory. A client that refused to start over a log file would turn a
// support inconvenience into an outage.
func TestNoDirectoryIsNotAnError(t *testing.T) {
	var echo bytes.Buffer
	s := New("", Options{Echo: &echo})
	if s.Available() {
		t.Error("Available() is true with no directory")
	}
	if s.Path() != "" {
		t.Errorf("Path() = %q, want empty", s.Path())
	}
	if s.LastError() == nil {
		t.Error("LastError() is nil — the Settings window has nothing to show the user")
	}
	if _, err := s.Write([]byte("still speaks\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := echo.String(); got != "still speaks\n" {
		t.Errorf("echo = %q, want the line", got)
	}
	if err := s.SetEnabled(false); err == nil {
		t.Error("SetEnabled on a sink with nowhere to write returned no error")
	}
}

// TestAsALogOutput is the integration check: this is what main.go does, and it
// is the seam #187 is about — log.Printf, which reached nothing on Windows, now
// reaches a file on every platform.
func TestAsALogOutput(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, Options{Redact: func(in string) string {
		return strings.ReplaceAll(in, "198.51.100.4", "<ip>")
	}})
	t.Cleanup(func() { _ = s.Close() })

	l := log.New(s, "", log.LstdFlags)
	l.Printf("[tun] ps failed: %s", "New-NetRoute -NextHop 198.51.100.4")

	got := readFile(t, filepath.Join(dir, FileName))
	if strings.Contains(got, "198.51.100.4") {
		t.Errorf("an address written through the standard log package reached the disk: %q", got)
	}
	if !strings.Contains(got, "[tun] ps failed") {
		t.Errorf("the line itself is missing: %q", got)
	}
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("the record lost its newline: %q", got)
	}
}
