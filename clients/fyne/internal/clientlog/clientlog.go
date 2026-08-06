// The desktop client's own log file (bacchus#187).
//
// Until this package existed, a Windows user could not produce a diagnostic
// log at all. main.go set the client's whole log sink to log.Printf, which
// writes to os.Stderr, and the shipping binary is linked -H=windowsgui — a GUI
// subsystem process gets no console, so os.Stderr has no valid destination and
// every line was discarded. main.go's own comment on the config-parse error had
// already worked out that this trap exists and routed exactly one message
// around it; nothing generalised it.
//
// # Why the file is on by default
//
// The two failures this log exists for are both SILENT. A client that reports
// "no coordinator reachable" for a datagram the kernel refused locally, and a
// client that says Protected while another VPN on the same machine has stopped
// working, both look like a working program until connecting stops. Neither
// gives the user a moment at which they would think to switch logging on, so an
// opt-in log is a log that is off during every failure it was built for.
//
// The forensic cost of a file on the disk of somebody in a hostile jurisdiction
// is real, and it is answered by three properties of this package rather than
// by defaulting to off:
//
//   - Every line is redacted before it reaches the disk (see Options.Redact and
//     redactHome), and the bar is decided for the SINK rather than per writer —
//     so a new writer inherits it instead of re-deriving it.
//   - MaxBytes with a single rotation, so this is a recent-history file and not
//     a diary. Worst case on disk is two files just over the cap.
//   - SetEnabled(false), which the Settings window offers, turns it off AND
//     deletes both files, so somebody who knows they are at risk can act on it.
//
// # Where it lives
//
// DefaultDir is <os.UserConfigDir>/Bacchus — %APPDATA%\Bacchus on Windows,
// $XDG_CONFIG_HOME/Bacchus on Linux. That is the directory this client already
// owns: appstate.configCandidates puts fyne-client.json there,
// appstate.DefaultDeviceCredDir puts the device identity under it, the Windows
// installer seeds the config into it, and the uninstaller already offers to
// remove the whole directory. A log written anywhere else would be residue the
// uninstaller misses — which for this product is the residue that matters most.
//
// XDG purism would put a log under $XDG_STATE_HOME instead. That is passed over
// deliberately: it would be a THIRD directory for a client that already keeps
// its secrets in one, and it would survive an uninstall that removes the other
// two. Being deleted with everything else is worth more here than being filed
// correctly.
//
// # Why the off-switch is not a config key
//
// The switch is the presence of a marker file (DisabledMarkerName) next to the
// log, not a field in fyne-client.json, and that is not a workaround for the
// config file being crowded. A config file that exists and does not parse
// leaves appstate.Config at its zero value — which is main.go's documented
// startup hazard and one of the things a support log is for. If "keep a log"
// were a config key, an unrelated JSON typo would silently turn logging off at
// exactly the launch where somebody needs it on. A marker file cannot be broken
// by a typo somewhere else in an unrelated file, and it is inside the directory
// the uninstaller removes, which the Fyne preferences store is not.
package clientlog

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// FileName is the live log. RotatedFileName is the one previous
	// generation. Two files, both capped, is the whole retention policy: a
	// support request is about something that happened in this session or the
	// one before it, and anything older is a diary nobody asked for.
	FileName = "bacchus.log"

	// RotatedFileName deliberately reads as a sibling of FileName rather than
	// as a timestamped archive. A user asked to send "the Bacchus log" should
	// find one obvious file and at most one obvious predecessor.
	RotatedFileName = "bacchus.log.1"

	// DisabledMarkerName is the off-switch. Its PRESENCE means off, so the
	// default state of a machine that has never been told anything is on —
	// which is the ruling this package implements. Contents are ignored; it is
	// written with a sentence in it only so that somebody who finds it can tell
	// what it does.
	DisabledMarkerName = "logging-off"
)

// DefaultMaxBytes caps the live file. The retired Windows client's log was
// about 35 KB after one session, so this holds several sessions of ordinary
// use and rather fewer of a client retrying a connect it cannot make — which is
// the case somebody is collecting a log for, and the case where the recent
// lines are the ones that matter.
const DefaultMaxBytes int64 = 256 << 10

// disabledMarkerBody is what a user finds if they open the marker file. It is
// not parsed and nothing reads it back.
const disabledMarkerBody = "Bacchus keeps no log file while this file exists.\n" +
	"Delete it, or turn the log back on in Settings, to start logging again.\n"

// DefaultDir is where the log lives: the same per-user directory this client
// already keeps its config and its device identity in. Returns "" when the OS
// cannot name a per-user config directory, which New reads as "no file on this
// machine" rather than guessing at a path.
//
// This MUST stay equal to the directory appstate.DefaultDeviceCredDir sits
// inside; TestDefaultDirMatchesTheConfigDirectory asserts it, because the two
// are derived independently and a drift would scatter the client's files
// across two directories with only one of them named in the uninstaller.
func DefaultDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "Bacchus")
}

// Options configures a Sink. The zero value is usable: no redaction, no echo,
// DefaultMaxBytes.
type Options struct {
	// Redact is applied to every line before it reaches the disk. It is
	// INJECTED rather than called by name so this package does not have to
	// import the enforcement package — which would drag netstack, wireguard-go
	// and gvisor into every binary and every test that merely wants to write a
	// line to a file. main.go passes enforcement.RedactAddresses, which is the
	// same address redaction that package already applies to its own output;
	// passing it here is what extends the bar to every OTHER writer.
	//
	// Nil means no address redaction. That is for tests; a production caller
	// that leaves this nil is shipping a log this package's own documentation
	// claims is redacted.
	Redact func(string) string

	// Echo receives every line as well, best-effort, and its errors are
	// ignored. main.go passes os.Stderr: on Linux a client started from a
	// terminal or by systemd still puts its output where its launcher expects,
	// and on Windows the write simply fails into the void that #187 is about.
	//
	// Echo is written even when the file is turned OFF. "Off" is a decision
	// about what this program leaves on the disk, not a decision to stop
	// producing diagnostics — a developer running the binary from a shell with
	// logging disabled should still see what it says.
	Echo io.Writer

	// MaxBytes caps the live file before rotation. Zero uses DefaultMaxBytes.
	MaxBytes int64
}

// Sink is the client's log destination: an io.Writer suitable for
// log.SetOutput, plus the controls the Settings window needs.
//
// Safe for concurrent use. The log package serialises its own writes, but
// SetEnabled is called from the UI goroutine while a connect goroutine is
// logging, so the lock is not decoration.
//
// Two PROCESSES can hold the same file briefly, and that is deliberate rather
// than overlooked: a second client refused by the single-instance guard opens
// this sink before it knows it is a second client, so that the refusal itself is
// recorded. It writes two or three lines and exits. Both platforms append
// atomically for a write that size, and a process writing that little never
// reaches the rotation threshold, so the interleaving is a few lines out of
// order in the worst case and nothing torn.
type Sink struct {
	mu      sync.Mutex
	dir     string
	max     int64
	redact  func(string) string
	echo    io.Writer
	f       *os.File
	size    int64
	off     bool  // the marker file is present
	lastErr error // why there is no file, for the UI to show
}

// New opens the log in dir, creating the directory if it is missing.
//
// It NEVER fails. A client that could not open its log file must still run —
// refusing to start a VPN because a diagnostic file could not be created would
// turn a support inconvenience into an outage. Whatever went wrong is kept in
// LastError for the Settings window to show, and every line still reaches
// Options.Echo.
//
// An empty dir means "this machine cannot name a per-user directory": no file,
// no error, echo only.
func New(dir string, opt Options) *Sink {
	s := &Sink{
		dir:    dir,
		max:    opt.MaxBytes,
		redact: opt.Redact,
		echo:   opt.Echo,
	}
	if s.max <= 0 {
		s.max = DefaultMaxBytes
	}
	if dir == "" {
		s.lastErr = errors.New("this system has no per-user configuration directory, so there is nowhere to keep a log")
		return s
	}
	s.off = markerPresent(dir)
	if !s.off {
		s.open()
	}
	return s
}

// markerPresent reports whether logging has been turned off in dir.
//
// Any stat error that is not "not there" counts as OFF. That is the direction
// that respects a choice already made: a user who turned logging off and whose
// directory later became unreadable should not silently get a log file back.
// It costs nothing, because a directory this cannot stat is one New could not
// have written to either.
func markerPresent(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, DisabledMarkerName))
	return !errors.Is(err, os.ErrNotExist)
}

// open attaches s to the live file. Caller holds s.mu (or is New).
func (s *Sink) open() {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		s.lastErr = err
		return
	}
	// 0600, and the directory 0700, on the same reasoning appstate.SaveConfig
	// gives for the config beside it: this file names the coordinators this
	// machine talks to and the errors it hit reaching them, and on a shared
	// machine that is nobody else's business.
	f, err := os.OpenFile(filepath.Join(s.dir, FileName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.lastErr = err
		return
	}
	size := int64(0)
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	s.f, s.size, s.lastErr = f, size, nil
}

// Write implements io.Writer for log.SetOutput.
//
// The log package emits one complete record per Write, so p is a whole line and
// redaction can be applied to it as a unit — no partial address can be split
// across two calls and escape the pattern.
//
// The return is always len(p) with a nil error on the echo-only path. A log
// sink that reported failures upward would make every call site in the client
// responsible for a disk problem it cannot do anything about; the failure is
// recorded in LastError and shown once, in Settings, where it can be acted on.
func (s *Sink) Write(p []byte) (int, error) {
	line := string(p)
	if s.redact != nil {
		line = s.redact(line)
	}
	line = redactHome(line)
	b := []byte(line)

	s.mu.Lock()
	if s.f != nil {
		s.rotateIfNeededLocked(int64(len(b)))
		if s.f != nil {
			n, err := s.f.Write(b)
			s.size += int64(n)
			if err != nil {
				s.lastErr = err
			}
		}
	}
	echo := s.echo
	s.mu.Unlock()

	if echo != nil {
		_, _ = echo.Write(b)
	}
	return len(p), nil
}

// rotateIfNeededLocked replaces the live file with an empty one once adding
// next bytes would take it past the cap, keeping the previous generation as
// RotatedFileName.
//
// The check is "would this write cross the line", not "has it already", so the
// cap is an upper bound rather than a threshold the file sits just above. A
// rotation that fails leaves the live file in place and keeps writing: an
// oversized log is a much smaller problem than a client that stops logging.
func (s *Sink) rotateIfNeededLocked(next int64) {
	if s.size == 0 || s.size+next <= s.max {
		return
	}
	live := filepath.Join(s.dir, FileName)
	if err := s.f.Close(); err != nil {
		s.lastErr = err
	}
	s.f = nil
	if err := os.Rename(live, filepath.Join(s.dir, RotatedFileName)); err != nil {
		s.lastErr = err
	}
	s.open()
}

// Path is the live log's full path, or "" when there is no file — because this
// machine has no per-user directory, because logging is off, or because opening
// it failed. main.go and the Settings window show it so a user can find the
// file without being talked through a directory tree, which is the half of #187
// that makes the log reachable by somebody who has never opened a terminal.
func (s *Sink) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return ""
	}
	return filepath.Join(s.dir, FileName)
}

// Enabled reports whether a log file is being kept.
func (s *Sink) Enabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.off
}

// Available reports whether this machine can keep a log at all — false only
// when there is no per-user directory to put one in. The Settings control is
// disabled rather than lying about a switch that cannot do anything.
func (s *Sink) Available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dir != ""
}

// LastError is why there is no file, or nil. Not an error return from Write:
// see that method's doc.
func (s *Sink) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// SetEnabled turns the log file on or off, and OFF ALSO DELETES IT.
//
// The delete is not a separate control, and that is the ruling rather than a
// simplification. Somebody switching this off is not tidying up; they are
// deciding that this machine should not carry a record of what this client did.
// Leaving the existing file behind would satisfy the letter of the switch and
// none of its purpose, and a second button they have to find as well is a
// second chance to leave the file there.
//
// Turning it back on starts a fresh file. The deleted one does not come back.
func (s *Sink) SetEnabled(on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return errors.New("this system has no per-user configuration directory, so there is nowhere to keep a log")
	}
	marker := filepath.Join(s.dir, DisabledMarkerName)
	if on {
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		s.off = false
		if s.f == nil {
			s.open()
		}
		return s.lastErr
	}

	// Stop writing BEFORE the marker and the delete, so nothing can land in a
	// file that is about to be removed and recreate it as a stray.
	if s.f != nil {
		if err := s.f.Close(); err != nil {
			s.lastErr = err
		}
		s.f, s.size = nil, 0
	}
	s.off = true
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(marker, []byte(disabledMarkerBody), 0o600); err != nil {
		return err
	}
	return s.deleteFilesLocked()
}

// deleteFilesLocked removes both generations. A file that is not there is not
// an error: the point is that it is gone afterwards, not that this call was the
// one that removed it.
func (s *Sink) deleteFilesLocked() error {
	var firstErr error
	for _, name := range []string{FileName, RotatedFileName} {
		if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close releases the file. The process exiting would do this anyway; it exists
// so a test can assert on a closed file and so a quit path can flush before the
// last teardown lines are lost.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// homeDir is resolved once. os.UserHomeDir reads an environment variable and
// cannot change under a running process, and resolving it per line would put a
// syscall on every log write.
var homeDir = func() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return strings.TrimRight(h, string(os.PathSeparator))
}()

// redactHome replaces this user's home directory with "~" wherever it appears.
//
// It is here rather than in the injected redactor because it is a property of
// the SINK, not of any one writer: every writer in this client can put a path
// in a line, because Go's os errors quote the path they failed on, and on both
// 1.0 platforms a per-user path contains the account name. "C:\Users\<name>\..."
// in a file the user is about to email to support is an identifier they did not
// choose to send, in a product whose users are chosen for not wanting to be
// identified.
//
// Best-effort by construction, and deliberately not case-folded: Windows paths
// compare case-insensitively, but the paths in these lines come back from the
// same os calls this process passed them to, so they match byte for byte. A
// path a user typed in a different case is missed, which is a smaller failure
// than mangling text that merely resembles a path.
func redactHome(s string) string {
	if homeDir == "" {
		return s
	}
	return strings.ReplaceAll(s, homeDir, "~")
}
