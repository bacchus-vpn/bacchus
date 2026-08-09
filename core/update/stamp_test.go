package update_test

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Reading the release stamp back out of a BUILT ARTIFACT, which is the one
// question release.yml's fleet job has to answer before it ships anything.
//
// The stamp arrives through `-ldflags -X …core/version.current=<semver>`, and a
// -X naming a symbol the linker cannot resolve is ignored SILENTLY, with a zero
// exit. So no step that checks the value it PASSED proves anything: the flag and
// the binary are two different facts, and only the binary's is the one that
// ships. Everything here is about reading the second one.
//
// WHAT WAS WRONG BEFORE (issue #254). release.yml read the stamp with
//
//	strings -a "dist-fleet/a/$name" | grep -qx "$SEMVER"
//
// which asks whether the value occupies a WHOLE LINE of `strings` output. Go
// packs its strings contiguously into one blob with no separators, so whether
// any given value lands on a line of its own is an accident of what happens to
// sit beside it. That is not a property of the stamp, and it fails in both
// directions:
//
//   - it went RED on a correctly stamped bacchus-netd, whose blob reads
//     "…48828125infinityClassANYQuestion…" through that region;
//   - and — measured, not feared — it goes GREEN on a bacchus-node and a
//     bacchus-coordinator built with NO -X at all, because core/version's own
//     source contains the literal "0.0.0" it reports when nothing stamped it,
//     and a dry run asserts exactly "0.0.0". A false pass on the precise defect
//     the step exists to catch. TestAnUnstampedBinaryStillContainsTheNumber
//     below pins that, so no future check reaches for a bytes search again.
//
// WHAT `go version -m` DOES, since the card left it open: with -trimpath it
// records no -ldflags at all, and the release build is -trimpath by ADR-0052 §5.
// Without -trimpath it records the flag STRING that was passed — the same string
// whether or not the linker resolved the symbol — which is the thing that proves
// nothing. Unusable for this, both ways round.
//
// WHAT THIS DOES INSTEAD: it decodes the Go string header the RUNTIME would read
// out of core/version.current, from the artifact's own data, at the address its
// symbol names. That is the same value version.Current() returns, obtained
// without executing anything, and it separates the two cases no value comparison
// can: a binary stamped 0.0.0 and a binary nobody stamped are the same NUMBER
// but not the same bytes — the second one has an empty string there.

// versionSymbol is the linker symbol every stamped build writes through. It is
// spelled out rather than derived because it is exactly what the -X on the other
// side of this names, and the two have to be the same text or the stamp is
// dropped without a word (core/version.TestEveryStampedBuildLinksTheVersionPackage
// is the other half of that).
const versionSymbol = "github.com/bacchus-vpn/bacchus/core/version.current"

// Environment read by TestReleaseArtifactsCarryTheStamp. Inert by default and
// made load-bearing by the one job that needs it — the same shape, and the same
// reason, as BACCHUS_ASN_RELEASE_TABLE, BACCHUS_REQUIRE_STAMP and
// BACCHUS_NETD_REQUIRE_NS: an assertion about artifacts cannot run where there
// are no artifacts, and a gate that quietly does nothing when its input is
// missing is not a gate.
const (
	stampEnv     = "BACCHUS_RELEASE_STAMP"
	artifactsEnv = "BACCHUS_RELEASE_ARTIFACTS"
)

// maxStamp bounds the length read out of the string header. A release is five
// or six characters; anything near this means the header was not a header — a
// wrong symbol, a wrong address, a file that is not what it claims — and reading
// a length the file supplied without a ceiling is how a parser turns a corrupt
// input into an allocation.
const maxStamp = 4096

// releaseStamp returns the release the linker actually placed in
// core/version.current in the ELF at path, and "" for a binary nothing stamped.
//
// A Go string is a two-word header — a pointer and a length — and `-X` writes
// both, pointing at string data the linker adds under the symbol name with a
// ".str" suffix. Reading the header rather than hunting for the text is what
// makes the answer exact: it is the same indirection the runtime follows, so
// there is nothing between this and what the binary would say about itself.
func releaseStamp(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s is not an ELF binary this can read (%v). The fleet artifacts "+
			"are built linux/amd64 by release.yml's fleet-binaries job; a Windows or macOS "+
			"artifact needs a reader for its own container format", path, err)
	}
	defer f.Close()

	if f.Class != elf.ELFCLASS64 {
		return "", fmt.Errorf("%s is a %v ELF; this reads the two-word string header of a 64-bit "+
			"build, which is every target the fleet ships", path, f.Class)
	}

	syms, err := f.Symbols()
	if err != nil {
		return "", fmt.Errorf("%s has no readable symbol table (%v). A stripped binary cannot be "+
			"asked what it was stamped with; the release build does not strip", path, err)
	}
	var header *elf.Symbol
	for i := range syms {
		if syms[i].Name == versionSymbol {
			header = &syms[i]
			break
		}
	}
	if header == nil {
		return "", fmt.Errorf("%s has no %s symbol, so it does not link core/version at all and no "+
			"-X aimed at that symbol reached it. Which binaries carry a stamp is decided by "+
			"`go list -deps` before this is asked", path, versionSymbol)
	}

	const word = 8
	raw, err := readVirtual(f, header.Value, 2*word)
	if err != nil {
		return "", fmt.Errorf("%s: reading the string header at %s: %w", path, versionSymbol, err)
	}
	ptr := f.ByteOrder.Uint64(raw[:word])
	length := f.ByteOrder.Uint64(raw[word:])
	if length == 0 {
		// The empty string core/version declares in source. It is the one value
		// no build can be stamped WITH, which is precisely what makes it the
		// signal that nothing stamped this one.
		return "", nil
	}
	if length > maxStamp {
		return "", fmt.Errorf("%s: %s claims a %d-byte string, which is not a release version — "+
			"the address read is not a string header", path, versionSymbol, length)
	}
	text, err := readVirtual(f, ptr, length)
	if err != nil {
		return "", fmt.Errorf("%s: reading the %d stamp bytes at 0x%x: %w", path, length, ptr, err)
	}
	return string(text), nil
}

// readVirtual returns n bytes at a virtual address, out of whichever loaded
// section covers it.
//
// SHT_NOBITS is handled rather than read: .bss occupies no space in the file and
// is zeroed at load, so an unstamped build — whose header holds a nil pointer
// and a zero length, and therefore lands there — must read as zeros instead of
// as whatever bytes happen to sit at that file offset.
func readVirtual(f *elf.File, addr, n uint64) ([]byte, error) {
	for _, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC == 0 || s.Size == 0 {
			continue
		}
		if addr < s.Addr || addr+n > s.Addr+s.Size {
			continue
		}
		if s.Type == elf.SHT_NOBITS {
			return make([]byte, n), nil
		}
		b := make([]byte, n)
		if _, err := s.ReadAt(b, int64(addr-s.Addr)); err != nil {
			return nil, fmt.Errorf("section %s: %w", s.Name, err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("no loaded section holds %d bytes at 0x%x", n, addr)
}

// THE RELEASE GATE. release.yml's fleet-binaries job names the artifacts it just
// built and the release they must carry, and this reads each one.
//
// It runs nowhere else. An ordinary `go test ./...` has no artifacts to look at,
// and the tests below it are what cover the reader itself on every pull request.
func TestReleaseArtifactsCarryTheStamp(t *testing.T) {
	want := os.Getenv(stampEnv)
	if want == "" {
		t.Skipf("%s is unset. This is release.yml's read-back of the fleet artifacts it just "+
			"built; on an ordinary run there are none", stampEnv)
	}
	files := strings.Fields(os.Getenv(artifactsEnv))
	if len(files) == 0 {
		t.Fatalf("%s is set to %q but %s names no artifact, so this would report green over an "+
			"empty set — the same shape as a -run filter matching no test. The caller derives "+
			"the list with `go list -deps`; if that produced nothing, that is the failure",
			stampEnv, want, artifactsEnv)
	}
	for _, path := range files {
		got, err := releaseStamp(path)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		switch {
		case got == "":
			t.Errorf("%s carries NO release stamp: core/version.current is empty in the shipped "+
				"bytes, so this binary reports 0.0.0 into the -min-serving-version fence and the "+
				"client force-update check for the life of the deployment (ADR-0015). The "+
				"-ldflags -X was passed and the linker dropped it, silently and with a zero exit, "+
				"which is why it is read back here rather than assumed.", path)
		case got != want:
			t.Errorf("%s carries release %q, and this release is %q. The binary and the tag "+
				"disagree about what is being shipped.", path, got, want)
		default:
			t.Logf("%s carries %s", filepath.Base(path), got)
		}
	}
}

// buildFixture links a binary that references core/version, with the -ldflags
// given, and returns its path.
//
// `go test -c` rather than one of the commands: it is the cheapest thing in this
// repository that links core/version through the real toolchain and the real
// linker, which is all the reader is being shown. GOOS/GOARCH are pinned so the
// fixture is an ELF wherever this test runs, including a developer's macOS or
// Windows machine — the reader is about the artifacts release.yml builds, and it
// should not go untested on a host that cannot produce one natively.
func buildFixture(t *testing.T, ldflags string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "fixture")
	args := []string{"test", "-c", "-trimpath", "-o", out}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "github.com/bacchus-vpn/bacchus/core/version")
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the fixture with ldflags %q: %v\n%s", ldflags, err, b)
	}
	return out
}

func TestTheStampIsReadBackOutOfTheLinkedBinary(t *testing.T) {
	const want = "3.14.15"
	bin := buildFixture(t, "-X "+versionSymbol+"="+want)
	got, err := releaseStamp(bin)
	if err != nil {
		t.Fatalf("reading the stamp back: %v", err)
	}
	if got != want {
		t.Fatalf("the binary was linked with %q and reads back as %q", want, got)
	}
}

// The case the old check could not see, and the reason this file exists: a build
// nobody stamped must read as unstamped, not as the number it would report.
func TestAnUnstampedBinaryReadsAsUnstamped(t *testing.T) {
	bin := buildFixture(t, "")
	got, err := releaseStamp(bin)
	if err != nil {
		t.Fatalf("reading an unstamped binary: %v", err)
	}
	if got != "" {
		t.Fatalf("a binary linked with no -X reads as %q; an unstamped build has an EMPTY "+
			"core/version.current, and that emptiness is the only thing that distinguishes it "+
			"from one stamped with the 0.0.0 it reports", got)
	}
}

// THE ONE THAT WOULD HAVE CAUGHT #254. The number is in the bytes of a binary
// nothing stamped — core/version's own source carries the "0.0.0" it reports
// when unstamped — so any check that searches the file for the release passes on
// a binary that has none. A dry run of release.yml asserts exactly "0.0.0", so
// this is not a hypothetical about some future value.
//
// It pins the PREMISE rather than the old shell, because the old shell is gone
// and the premise is what would make somebody write it again.
func TestAnUnstampedBinaryStillContainsTheNumber(t *testing.T) {
	bin := buildFixture(t, "")
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}
	if !bytes.Contains(raw, []byte("0.0.0")) {
		t.Skip("this build of core/version no longer carries the literal 0.0.0 anywhere in its " +
			"bytes, so the false pass this pins is not reproducible here. The reader above does " +
			"not depend on it either way")
	}
	got, err := releaseStamp(bin)
	if err != nil {
		t.Fatalf("reading the stamp: %v", err)
	}
	if got != "" {
		t.Fatalf("the unstamped fixture reads as %q", got)
	}
	t.Log("an unstamped binary contains the bytes 0.0.0 and carries no stamp: a check that " +
		"searches the file for the release cannot tell a stamped build from an unstamped one")
}

// A -X aimed at a symbol the linker cannot resolve. The build SUCCEEDS with a
// zero exit and the flag is dropped without a word, which is the whole reason
// the value is read out of the binary instead of being taken from the command
// line that produced it.
func TestAnIgnoredLdflagIsVisibleInTheBinary(t *testing.T) {
	bin := buildFixture(t, "-X github.com/bacchus-vpn/bacchus/core/version.thereIsNoSuchVar=9.9.9")
	got, err := releaseStamp(bin)
	if err != nil {
		t.Fatalf("reading the stamp: %v", err)
	}
	if got != "" {
		t.Fatalf("a -X naming an unresolvable symbol left %q in core/version.current", got)
	}
}

// The reader must not invent an answer for a binary that does not link
// core/version at all. release.yml decides that with `go list -deps` before it
// gets here, and the two have to agree about what "no stamp" means: no symbol is
// a different fact from an empty one, and only the second is a defect.
func TestABinaryWithoutTheSymbolIsAnError(t *testing.T) {
	out := filepath.Join(t.TempDir(), "nover")
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "github.com/bacchus-vpn/bacchus/cmd/asn-stage")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build a command that does not link core/version: %v\n%s", err, b)
	}
	if _, err := releaseStamp(out); err == nil {
		t.Fatal("a binary with no core/version.current symbol read back without an error; " +
			"'this binary carries no stamp' and 'this binary has no stamp to carry' are " +
			"different answers and must not collapse into one")
	}
}
