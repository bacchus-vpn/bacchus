// Windows application-manifest coverage (bacchus#136).
//
// bacchus-fyne.manifest is the reviewable source; rsrc_windows_amd64.syso is
// the COFF object the Go linker actually embeds, and it is a binary nobody can
// read in a diff. That asymmetry is the whole risk: edit the manifest, forget
// to regenerate the .syso, and every check in this repo stays green while the
// shipping binary carries the OLD manifest — or, if the .syso were ever
// regenerated wrong, no manifest at all. Nothing else in the build looks
// inside it.
//
// So this walks the resource directory in the committed object and asserts,
// on every push and on every platform, that what Windows will read at process
// creation is byte-for-byte the file next to it and that it asks for
// elevation. That is the one property bacchus#136's second ruling turns on:
// without it a double-click runs unelevated, every connect fails at the first
// administrator operation, and the only clue is one error string at the far
// end of the chain (bacchus#135).
//
// Deliberately NOT a Windows-only test. The .syso is Windows-only *cargo*, but
// it is committed data, and a check that only runs on the Windows job is a
// check a Linux-only contributor never sees fail.
package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

const (
	// manifestSource is the reviewable half. It is also what
	// `rsrc -manifest bacchus-fyne.manifest -arch <arch>` is run over to
	// regenerate the object — see clients/fyne/README.md.
	manifestSource = "bacchus-fyne.manifest"

	// rtManifest is RT_MANIFEST, and manifestResourceID is
	// CREATEPROCESS_MANIFEST_RESOURCE_ID: the type/id pair Windows looks for
	// when it decides how to start a process. A manifest embedded under any
	// other pair is inert, which is a failure that looks exactly like success
	// in a file listing.
	rtManifest          = 24
	manifestResourceID  = 1
	requestedExecLevel  = `level="requireAdministrator"`
	resourceDirHeader   = 16 // IMAGE_RESOURCE_DIRECTORY
	resourceDirEntry    = 8  // IMAGE_RESOURCE_DIRECTORY_ENTRY
	resourceDataEntry   = 16 // IMAGE_RESOURCE_DATA_ENTRY
	subdirectoryFlag    = 0x80000000
	resourceOffsetMask  = 0x7fffffff
	manifestResourceMin = 1 // at least one .syso must exist, or nothing is embedded at all
)

// TestManifestAsksForElevation checks the source file on its own. It is the
// half a reviewer can read, and the requestedExecutionLevel is the only line
// in it that changes what Windows does.
func TestManifestAsksForElevation(t *testing.T) {
	b, err := os.ReadFile(manifestSource)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", manifestSource, err)
	}
	if !bytes.Contains(b, []byte(requestedExecLevel)) {
		t.Fatalf("%s does not request %s — without it Windows starts the client unelevated, no UAC prompt appears, and every connect fails at the first administrator operation", manifestSource, requestedExecLevel)
	}
}

// TestEmbeddedManifestMatchesSource is the drift guard, and the reason the
// binary in the tree is safe to have: the .syso can only ever be a faithful
// copy of the file beside it.
//
// Mutation check: edit one character of bacchus-fyne.manifest without running
// rsrc again, and this names the mismatch. Delete the .syso and it says
// nothing is embedded.
func TestEmbeddedManifestMatchesSource(t *testing.T) {
	want, err := os.ReadFile(manifestSource)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", manifestSource, err)
	}

	sysos, err := filepath.Glob("*.syso")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(sysos) < manifestResourceMin {
		t.Fatal("no *.syso in this package — the Go linker has nothing to embed, so the shipping binary asks Windows for nothing; regenerate it (see README.md)")
	}

	for _, path := range sysos {
		got := manifestResourceIn(t, path)
		if !bytes.Equal(got, want) {
			t.Errorf("%s embeds a manifest that is not %s (%d bytes embedded, %d in the source) — regenerate it: rsrc -manifest %s -arch <arch> -o %s",
				path, manifestSource, len(got), len(want), manifestSource, path)
		}
	}
}

// manifestResourceIn returns the bytes of the single RT_MANIFEST resource with
// id 1 in a COFF object's .rsrc section, failing the test if the object holds
// anything other than exactly one.
//
// The layout is the ordinary PE resource tree — three nested
// IMAGE_RESOURCE_DIRECTORYs keyed type, then name/id, then language, with an
// IMAGE_RESOURCE_DATA_ENTRY at the leaf. In an OBJECT rather than an image the
// leaf's OffsetToData is section-relative with a relocation against it, rather
// than an RVA, which is what lets this read the payload straight out of the
// section bytes.
func manifestResourceIn(t *testing.T, path string) []byte {
	t.Helper()
	f, err := pe.Open(path)
	if err != nil {
		t.Fatalf("pe.Open %s: %v", path, err)
	}
	defer f.Close()

	sec := f.Section(".rsrc")
	if sec == nil {
		t.Fatalf("%s has no .rsrc section, so it carries no resources at all", path)
	}
	d, err := sec.Data()
	if err != nil {
		t.Fatalf("%s .rsrc data: %v", path, err)
	}

	typeOff, ok := subdirectoryFor(t, d, 0, rtManifest)
	if !ok {
		t.Fatalf("%s has no RT_MANIFEST (type %d) resource — whatever it embeds, Windows will not read it as a manifest", path, rtManifest)
	}
	idOff, ok := subdirectoryFor(t, d, typeOff, manifestResourceID)
	if !ok {
		t.Fatalf("%s has an RT_MANIFEST resource but not under id %d (CREATEPROCESS_MANIFEST_RESOURCE_ID), so it does not apply to this process", path, manifestResourceID)
	}
	// One language subdirectory, whatever its id: the manifest is XML and
	// carries no localized text, so which LANGID rsrc stamped is immaterial.
	langCount, entries := directoryEntries(t, d, idOff)
	if langCount != 1 {
		t.Fatalf("%s has %d language entries under the manifest resource, want exactly 1", path, langCount)
	}
	_, offset := entries(0)
	if offset&subdirectoryFlag != 0 {
		t.Fatalf("%s: the manifest's language entry points at another directory, not at data", path)
	}
	if int(offset)+resourceDataEntry > len(d) {
		t.Fatalf("%s: data entry at %#x runs past the .rsrc section", path, offset)
	}
	dataOff := binary.LittleEndian.Uint32(d[offset:])
	size := binary.LittleEndian.Uint32(d[offset+4:])
	if int(dataOff)+int(size) > len(d) {
		t.Fatalf("%s: manifest payload at %#x+%d runs past the .rsrc section (%d bytes)", path, dataOff, size, len(d))
	}
	return d[dataOff : dataOff+size]
}

// directoryEntries returns the entry count of the resource directory at off
// and an accessor for its (id, offset) pairs.
func directoryEntries(t *testing.T, d []byte, off uint32) (int, func(i int) (uint32, uint32)) {
	t.Helper()
	if int(off)+resourceDirHeader > len(d) {
		t.Fatalf("resource directory at %#x runs past the .rsrc section", off)
	}
	named := binary.LittleEndian.Uint16(d[off+12:])
	ids := binary.LittleEndian.Uint16(d[off+14:])
	n := int(named) + int(ids)
	return n, func(i int) (uint32, uint32) {
		e := int(off) + resourceDirHeader + i*resourceDirEntry
		if e+resourceDirEntry > len(d) {
			t.Fatalf("resource entry %d at %#x runs past the .rsrc section", i, e)
		}
		return binary.LittleEndian.Uint32(d[e:]), binary.LittleEndian.Uint32(d[e+4:])
	}
}

// subdirectoryFor finds the entry with id in the directory at off and returns
// the offset of the subdirectory it points at.
func subdirectoryFor(t *testing.T, d []byte, off uint32, id uint32) (uint32, bool) {
	t.Helper()
	n, entry := directoryEntries(t, d, off)
	for i := 0; i < n; i++ {
		gotID, gotOff := entry(i)
		if gotID != id || gotOff&subdirectoryFlag == 0 {
			continue
		}
		return gotOff & resourceOffsetMask, true
	}
	return 0, false
}
