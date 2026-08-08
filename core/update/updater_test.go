package update_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/update"
)

// writeSource populates a source layout — manifest.json plus blobs/<hex> — in a
// fresh directory and returns it. This is exactly what a mirror, a release page or
// a USB stick holds; nothing about the layout is signed and nothing about it is
// trusted.
func writeSource(t *testing.T, b update.Bundle, blobs ...[]byte) string {
	t.Helper()
	dir := t.TempDir()
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, update.ManifestName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, update.BlobDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, blob := range blobs {
		a := artifactOf("linux", "amd64", update.RoleNode, blob)
		if err := os.WriteFile(filepath.Join(dir, update.BlobDir, a.Name()), blob, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// updaterFor builds an Updater against a source directory, for a build that says
// it is `current`.
func updaterFor(t *testing.T, c chain, srcDir, target, current string, tweak func(*update.Config)) *update.Updater {
	t.Helper()
	cfg := update.Config{
		Root:           c.rootPub,
		Source:         update.NewDirSource(srcDir),
		Target:         target,
		Role:           update.RoleNode,
		OS:             "linux",
		Arch:           "amd64",
		StatePath:      filepath.Join(t.TempDir(), "update-state.json"),
		CurrentRelease: current,
		Now:            func() time.Time { return testNow },
		Log:            func(string, ...any) {},
	}
	if tweak != nil {
		tweak(&cfg)
	}
	u, err := update.NewUpdater(cfg)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	return u
}

func TestCheckAppliesANewerRelease(t *testing.T) {
	c := newChain(t, testNow)
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	dir := writeSource(t, c.bundle(t, sampleManifest("0.5.0", 3, testNow, a)), releaseBytes)

	u := updaterFor(t, c, dir, target, "0.4.1", nil)
	out, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !out.Applied || out.Release != "0.5.0" {
		t.Fatalf("Check = %+v, want an applied 0.5.0", out)
	}
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("the target was not replaced: %q", got)
	}
}

func TestCheckDoesNothingWhenTheReleaseIsNotNewer(t *testing.T) {
	c := newChain(t, testNow)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	dir := writeSource(t, c.bundle(t, sampleManifest("0.5.0", 3, testNow, a)), releaseBytes)

	for _, current := range []string{"0.5.0", "0.6.0"} {
		target := installed(t)
		u := updaterFor(t, c, dir, target, current, nil)
		out, err := u.Check(context.Background())
		if err != nil {
			t.Fatalf("Check at %s: %v", current, err)
		}
		if !out.UpToDate || out.Applied {
			t.Fatalf("Check at %s = %+v, want up to date", current, out)
		}
		// Never a downgrade, even from a perfectly signed manifest.
		assertUntouched(t, target)
	}
}

func TestCheckDoesNothingWhenTheManifestHasNoRowForThisBuild(t *testing.T) {
	c := newChain(t, testNow)
	a := artifactOf("windows", "amd64", update.RoleClient, releaseBytes)
	dir := writeSource(t, c.bundle(t, sampleManifest("0.5.0", 3, testNow, a)))

	target := installed(t)
	u := updaterFor(t, c, dir, target, "0.4.1", nil)
	out, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !out.NoArtifact {
		t.Fatalf("Check = %+v, want NoArtifact", out)
	}
	assertUntouched(t, target)
}

// The three refusals the card names, each asserted on the bytes at the target
// path rather than on the error alone.
func TestARefusedReleaseLeavesTheRunningBinaryInPlace(t *testing.T) {
	c := newChain(t, testNow)
	good := sampleManifest("0.5.0", 3, testNow, artifactOf("linux", "amd64", update.RoleNode, releaseBytes))

	otherPub, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		bundle update.Bundle
		blob   []byte
		want   error
	}{
		{
			name: "unsigned: a bare manifest body where a signed one belongs",
			bundle: func() update.Bundle {
				body, err := json.Marshal(good)
				if err != nil {
					t.Fatal(err)
				}
				return update.Bundle{Manifest: body, Cert: c.cert}
			}(),
			blob: releaseBytes,
			want: delegation.ErrBadSignature,
		},
		{
			name: "signed by the wrong key",
			bundle: func() update.Bundle {
				signed, err := update.Sign(otherPriv, good)
				if err != nil {
					t.Fatal(err)
				}
				return update.Bundle{Manifest: signed, Cert: c.cert}
			}(),
			blob: releaseBytes,
			want: delegation.ErrBadSignature,
		},
		{
			name: "delegated by a root this build does not trust",
			bundle: func() update.Bundle {
				signed, err := update.Sign(otherPriv, good)
				if err != nil {
					t.Fatal(err)
				}
				return update.Bundle{
					Manifest: signed,
					Cert:     mintCert(t, otherPriv, otherPub, delegation.RoleUpdate, "z9", testNow.Add(-time.Hour), testNow.Add(time.Hour)),
				}
			}(),
			blob: releaseBytes,
			want: delegation.ErrBadSignature,
		},
		{
			name:   "corrupted artifact bytes under a valid signature",
			bundle: c.bundle(t, good),
			blob:   bytes.Replace(releaseBytes, []byte("NEW"), []byte("BAD"), 1),
			want:   update.ErrHashMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := installed(t)
			dir := t.TempDir()
			raw, err := tc.bundle.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, update.ManifestName), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, update.BlobDir), 0o755); err != nil {
				t.Fatal(err)
			}
			// Served under the name the GENUINE artifact would have, which is the only
			// name the manifest can be made to ask for.
			name := artifactOf("linux", "amd64", update.RoleNode, releaseBytes).Name()
			if err := os.WriteFile(filepath.Join(dir, update.BlobDir, name), tc.blob, 0o644); err != nil {
				t.Fatal(err)
			}

			u := updaterFor(t, c, dir, target, "0.4.1", nil)
			out, err := u.Check(context.Background())
			if err == nil {
				t.Fatalf("Check ACCEPTED a release that must be refused: %+v", out)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Check = %v, want %v", err, tc.want)
			}
			assertUntouched(t, target)
		})
	}
}

// The persisted floor is what stops a replay. An attacker who can serve bytes may
// serve an OLD, genuinely signed manifest; a peer that held its floor only in
// memory would take it after any restart.
func TestThePersistedFloorRefusesAReplayedOlderRelease(t *testing.T) {
	c := newChain(t, testNow)
	target := installed(t)
	statePath := filepath.Join(t.TempDir(), "state.json")

	newer := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	newDir := writeSource(t, c.bundle(t, sampleManifest("0.5.0", 9, testNow, newer)), releaseBytes)
	u := updaterFor(t, c, newDir, target, "0.4.1", func(cfg *update.Config) { cfg.StatePath = statePath })
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatalf("first Check: %v", err)
	}

	// A different, genuinely signed manifest from an older generation, served after a
	// restart — a NEW Updater, so nothing is remembered in memory.
	oldBytes := []byte("#!/bin/false\nI AM THE BURNED RELEASE\n")
	older := artifactOf("linux", "amd64", update.RoleNode, oldBytes)
	oldDir := writeSource(t, c.bundle(t, sampleManifest("0.4.9", 4, testNow, older)))
	if err := os.WriteFile(filepath.Join(oldDir, update.BlobDir, older.Name()), oldBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	u2 := updaterFor(t, c, oldDir, target, "0.4.1", func(cfg *update.Config) { cfg.StatePath = statePath })
	if _, err := u2.Check(context.Background()); !errors.Is(err, update.ErrRollback) {
		t.Fatalf("Check on a replayed older manifest = %v, want ErrRollback", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("a replayed release was applied: %q", got)
	}
}

// The client's shape: stage while the tunnel is up, publish at a boundary where
// nothing is connected.
func TestDeferStagesAndAppliesAtABoundary(t *testing.T) {
	c := newChain(t, testNow)
	target := installed(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	dir := writeSource(t, c.bundle(t, sampleManifest("0.5.0", 3, testNow, a)), releaseBytes)

	u := updaterFor(t, c, dir, target, "0.4.1", func(cfg *update.Config) {
		cfg.Defer = true
		cfg.StatePath = statePath
	})
	out, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !out.Deferred || out.Applied {
		t.Fatalf("Check = %+v, want a deferred stage", out)
	}
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("a deferred check published the release anyway: %q", got)
	}

	// A second check while still deferred must not re-download or publish.
	if out2, err := u.Check(context.Background()); err != nil || out2.Applied {
		t.Fatalf("second Check = %+v, %v", out2, err)
	}

	// The boundary, in a fresh process: the staged file is re-verified and published.
	u2 := updaterFor(t, c, dir, target, "0.4.1", func(cfg *update.Config) {
		cfg.Defer = true
		cfg.StatePath = statePath
	})
	applied, err := u2.ApplyPending()
	if err != nil {
		t.Fatalf("ApplyPending: %v", err)
	}
	if !applied.Applied || applied.Release != "0.5.0" {
		t.Fatalf("ApplyPending = %+v", applied)
	}
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("the boundary did not publish the release: %q", got)
	}
	// And a second boundary has nothing to do.
	if _, err := u2.ApplyPending(); !errors.Is(err, update.ErrNoPending) {
		t.Fatalf("a second ApplyPending = %v, want ErrNoPending", err)
	}
}

// A staged file that was tampered with between the stage and the boundary is
// refused and forgotten, not published.
func TestApplyPendingRefusesATamperedStagedFile(t *testing.T) {
	c := newChain(t, testNow)
	target := installed(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	dir := writeSource(t, c.bundle(t, sampleManifest("0.5.0", 3, testNow, a)), releaseBytes)

	u := updaterFor(t, c, dir, target, "0.4.1", func(cfg *update.Config) {
		cfg.Defer = true
		cfg.StatePath = statePath
	})
	out, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := os.WriteFile(out.Staged, bytes.Repeat([]byte("z"), len(releaseBytes)), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := u.ApplyPending(); !errors.Is(err, update.ErrHashMismatch) {
		t.Fatalf("ApplyPending on a tampered staging file = %v, want ErrHashMismatch", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("tampered bytes were published: %q", got)
	}
	if _, err := u.ApplyPending(); !errors.Is(err, update.ErrNoPending) {
		t.Fatalf("the tampered pending record was not forgotten: %v", err)
	}
}

// The gate is checked BEFORE anything is fetched. A refusal is not a fetch that
// fails; it is no fetch. That is the whole property for the client, whose fetch
// must ride inside its own tunnel or not happen.
func TestTheGateStopsTheFetchBeforeItHappens(t *testing.T) {
	c := newChain(t, testNow)
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	dir := writeSource(t, c.bundle(t, sampleManifest("0.5.0", 3, testNow, a)), releaseBytes)

	asked := 0
	u := updaterFor(t, c, dir, target, "0.4.1", func(cfg *update.Config) {
		cfg.Source = countingSource{inner: update.NewDirSource(dir), n: &asked}
		cfg.Gate = func() error { return errors.New("not routed") }
	})
	out, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !out.Gated {
		t.Fatalf("Check = %+v, want Gated", out)
	}
	if asked != 0 {
		t.Fatalf("the gate refused and the source was still asked %d time(s)", asked)
	}
	assertUntouched(t, target)
}

type countingSource struct {
	inner update.Source
	n     *int
}

func (s countingSource) String() string { return s.inner.String() }
func (s countingSource) Manifest(ctx context.Context) ([]byte, error) {
	*s.n++
	return s.inner.Manifest(ctx)
}
func (s countingSource) Artifact(ctx context.Context, a update.Artifact) (io.ReadCloser, error) {
	*s.n++
	return s.inner.Artifact(ctx, a)
}

func TestNewUpdaterRefusesAHalfConfiguration(t *testing.T) {
	c := newChain(t, testNow)
	base := update.Config{
		Root:      c.rootPub,
		Source:    update.NewDirSource(t.TempDir()),
		Target:    filepath.Join(t.TempDir(), "bin"),
		Role:      update.RoleNode,
		StatePath: filepath.Join(t.TempDir(), "s.json"),
	}
	cases := map[string]func(*update.Config){
		"no source":    func(c *update.Config) { c.Source = nil },
		"no state":     func(c *update.Config) { c.StatePath = "" },
		"unknown role": func(c *update.Config) { c.Role = "shell" },
		"no anchor":    func(c *update.Config) { c.Root = nil },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base
			break_(&cfg)
			if _, err := update.NewUpdater(cfg); err == nil {
				t.Fatal("NewUpdater accepted a configuration that cannot update anything")
			}
		})
	}
}

// An unstamped build refuses to update itself: it cannot tell whether a release is
// newer than itself, and 0.0.0 is below everything.
func TestAnUnstampedBuildRefusesToUpdateItself(t *testing.T) {
	c := newChain(t, testNow)
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	dir := writeSource(t, c.bundle(t, sampleManifest("0.5.0", 3, testNow, a)), releaseBytes)

	u := updaterFor(t, c, dir, target, "", nil) // no CurrentRelease, and the test binary is unstamped
	if _, err := u.Check(context.Background()); err == nil {
		t.Fatal("an unstamped build updated itself")
	}
	assertUntouched(t, target)
}

// The HTTP source over a real server, including the redirect and scheme rules.
func TestHTTPSource(t *testing.T) {
	c := newChain(t, testNow)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	bundle := c.bundle(t, sampleManifest("0.5.0", 3, testNow, a))
	raw, err := bundle.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		switch r.URL.Path {
		case "/" + update.ManifestName:
			w.Write(raw)
		case "/" + update.BlobDir + "/" + a.Name():
			w.Write(releaseBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	src, err := update.NewHTTPSource(srv.URL)
	if err != nil {
		t.Fatalf("NewHTTPSource(%s): %v", srv.URL, err)
	}
	target := installed(t)
	u, err := update.NewUpdater(update.Config{
		Root: c.rootPub, Source: src, Target: target, Role: update.RoleNode,
		OS: "linux", Arch: "amd64",
		StatePath:      filepath.Join(t.TempDir(), "state.json"),
		CurrentRelease: "0.4.1",
		Now:            func() time.Time { return testNow },
		Log:            func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check over HTTP: %v", err)
	}
	if !out.Applied {
		t.Fatalf("Check = %+v", out)
	}
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatal("the release was not applied")
	}
	// The User-Agent carries no version: a mirror must not be handed a fleet
	// inventory by the mechanism that exists to patch it.
	if gotUA == "" || gotUA != "bacchus-update" {
		t.Fatalf("User-Agent = %q, want the fixed versionless string", gotUA)
	}
}

func TestHTTPSourceRefusesCleartextToARemoteHost(t *testing.T) {
	for _, bad := range []string{
		"http://example.invalid/releases",
		"http://localhost.example.invalid/r",
		"ftp://example.invalid/r",
		"//example.invalid/r",
	} {
		if _, err := update.NewHTTPSource(bad); !errors.Is(err, update.ErrInsecureSource) {
			t.Errorf("NewHTTPSource(%q) = %v, want ErrInsecureSource", bad, err)
		}
	}
	// Loopback is exempt, decided from the parsed host rather than from a prefix.
	for _, ok := range []string{"http://127.0.0.1:8080/r", "http://localhost:1/r", "http://[::1]:9/r", "https://example.invalid/r"} {
		if _, err := update.NewHTTPSource(ok); err != nil {
			t.Errorf("NewHTTPSource(%q) = %v, want accept", ok, err)
		}
	}
}
