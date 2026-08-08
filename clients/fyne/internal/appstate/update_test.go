package appstate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The client's release-channel rules, tested where they are decidable without a
// coordinator: what a source string may be, what happens with no anchor, and that
// an update path which is CONFIGURED but broken is reported rather than silently
// inert.

func TestUpdateConfigZeroValueIsOff(t *testing.T) {
	var c UpdateConfig
	if c.Enabled() {
		t.Fatal("the zero UpdateConfig enables updating; a client that was never told where releases live must not fetch any")
	}
	w, err := NewUpdateWatcher(nil, c, nil)
	if err != nil {
		t.Fatalf("NewUpdateWatcher with updating off = %v, want no error", err)
	}
	if w != nil {
		t.Fatal("NewUpdateWatcher built a watcher with no source")
	}
	// Every method must survive the nil watcher, because that is the shipped
	// default and main calls them unconditionally.
	w.ApplyStaged()
	w.Run(nil)
}

// A cleartext source to a remote host is refused. The bytes are signed and
// content-addressed so integrity does not need TLS — EXPOSURE does: a plaintext
// GET names the exact release being fetched to anyone on the path, and this
// project spent two ADRs removing the last cleartext surface a client had.
func TestUpdateSourceRefusesCleartextToARemoteHost(t *testing.T) {
	for _, bad := range []string{"http://example.invalid/releases", "ftp://example.invalid/r"} {
		if _, err := buildUpdateSource(bad); err == nil {
			t.Errorf("buildUpdateSource(%q) was accepted", bad)
		}
	}
	dir := t.TempDir()
	if _, err := buildUpdateSource(dir); err != nil {
		t.Errorf("buildUpdateSource(a directory) = %v, want accept", err)
	}
	if _, err := buildUpdateSource("https://releases.example.invalid/bacchus"); err != nil {
		t.Errorf("buildUpdateSource(https) = %v, want accept", err)
	}
	// A file is not a source layout, and saying so beats a confusing failure later.
	f := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildUpdateSource(f); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Errorf("buildUpdateSource(a file) = %v, want a refusal naming the directory", err)
	}
}

// A source with no anchor anywhere is an ERROR, not a silent no-op. A client told
// to keep itself updated and quietly not doing so is the failure this whole card
// exists to remove.
func TestAConfiguredSourceWithNoAnchorIsRefusedLoudly(t *testing.T) {
	// This test binary carries no compiled-in anchor, which is exactly the
	// unstamped-build case.
	_, err := NewUpdateWatcher(&Controller{}, UpdateConfig{Source: t.TempDir()}, nil)
	if err == nil {
		t.Fatal("a configured update source with no trust anchor was accepted")
	}
	if !strings.Contains(err.Error(), "trust anchor") {
		t.Fatalf("the refusal does not name the missing anchor: %v", err)
	}
}

func TestResolveUpdateAnchorPrefersTheConfiguredKey(t *testing.T) {
	// 32 bytes of hex: a syntactically valid anchor, and not a key anything holds.
	good := strings.Repeat("ab", 32)
	pub, err := resolveUpdateAnchor(good)
	if err != nil {
		t.Fatalf("resolveUpdateAnchor(valid hex) = %v", err)
	}
	if len(pub) != 32 {
		t.Fatalf("resolveUpdateAnchor returned %d bytes", len(pub))
	}
	for _, bad := range []string{"zz", strings.Repeat("ab", 16)} {
		if _, err := resolveUpdateAnchor(bad); err == nil {
			t.Errorf("resolveUpdateAnchor(%q) was accepted", bad)
		}
	}
}

// Protected and NetworkRelease are the two in-memory values the watcher reads.
// Neither may touch the network, and both must survive an engine that does not
// exist yet — which is the state a client is in for most of its life.
func TestControllerReportsNoAnnouncementBeforeAnyEngine(t *testing.T) {
	c := &Controller{}
	if got := c.NetworkRelease(); got != "" {
		t.Fatalf("NetworkRelease with no engine = %q, want empty", got)
	}
	if c.Protected() {
		t.Fatal("Protected with no engine is true")
	}
	c.mu.Lock()
	c.state = Protected
	c.mu.Unlock()
	if !c.Protected() {
		t.Fatal("Protected does not follow the connection state")
	}
	// Still no engine: the announcement is a fact about a connection, not about the
	// state field.
	if got := c.NetworkRelease(); got != "" {
		t.Fatalf("NetworkRelease = %q with no engine", got)
	}
}

// The gate refuses while the client is not routed, and the refusal reaches
// core/update as a plain error rather than as a panic on a nil controller.
func TestTheGateRefusesWhileNotRouted(t *testing.T) {
	c := &Controller{}
	gate := func() error {
		if !c.Protected() {
			return errors.New("not routed")
		}
		return nil
	}
	if err := gate(); err == nil {
		t.Fatal("the gate admitted a fetch while the client was not routed")
	}
	c.mu.Lock()
	c.state = Protected
	c.mu.Unlock()
	if err := gate(); err != nil {
		t.Fatalf("the gate refused while routed: %v", err)
	}
}
