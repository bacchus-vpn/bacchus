package atomicfile

import "os"

// syncDirHandle is a documented no-op on Windows. What that costs, what Windows
// documents instead, and what is still unanswered are all below rather than
// implied by a function that returns nil.
//
// # Why the direct form cannot be used
//
// FlushFileBuffers documents that "the file handle must have the GENERIC_WRITE
// access right". os.Open asks for none, so calling Sync on the handle it returns
// produces ERROR_ACCESS_DENIED on every call — a failure the caller cannot act
// on, and returning it would fail every WriteDurable on this platform for a
// reason that has nothing to do with the write.
//
// This file used to give the reason as "a directory handle is never opened for
// writing", which is not what the documentation says. NtFlushBuffersFileEx — the
// routine FlushFileBuffers issues — excludes directory handles from exactly one
// of its four flush modes (FLUSH_FLAGS_FILE_DATA_SYNC_ONLY, "not valid with
// volume or directory handles") and from none of the others, so a directory
// handle is contemplated at that level. The handle Go hands this function is the
// problem, not the object it names.
//
// # What Windows documents for durability, and it is one lever, not two
//
// Issue #228 asked whether NTFS needs a separate step for the CREATE case at
// all. The documentation answers most of it:
//
//   - FlushFileBuffers is NtFlushBuffersFileEx with flags 0, documented as "File
//     data and metadata in the file cache will be written, and the underlying
//     storage is synchronized to flush its cache. Windows file systems
//     supported: NTFS, ReFS, FAT, exFAT." The sibling flag
//     FLUSH_FLAGS_FILE_DATA_ONLY ("No metadata is written and the underlying
//     storage is not synchronized") is the explicit opt-out, which is what makes
//     metadata part of the default rather than an accident of wording.
//   - Win32's File Caching page: "File system metadata is always cached.
//     Therefore, to store any metadata changes to disk, the file must either be
//     flushed or be opened with FILE_FLAG_WRITE_THROUGH."
//
// Those two are the only levers Windows offers an application, and they are the
// same lever: the seed writers already flush the handle. So the create case here
// is NOT a platform where a stronger call is being skipped — there is no
// stronger call documented to make.
//
// # What is still unanswered, and why nothing is invented for it
//
// Microsoft documents THE FILE'S metadata. It never says whether that includes
// the entry in the file's PARENT directory, which is the entire question: losing
// that entry is what leaves no file at all. NTFS journals metadata write-ahead
// and the index-entry insert belongs to the same create transaction, so it is
// very likely covered — but that is an inference about internals rather than a
// guarantee an application is given, and no in-process test can distinguish the
// two. Issue #238 is the power-loss run that can; #228 stays open until it does.
//
// MoveFileEx with MOVEFILE_WRITE_THROUGH is not the missing piece either, and
// this file used to imply that it was ("Windows expresses it at the rename
// instead"). Its documented guarantee is narrower than that reads: "Setting this
// value guarantees that a move performed as a copy and delete operation is
// flushed to disk before the function returns. The flush occurs at the end of
// the copy operation." A same-volume rename is not a copy and delete, so the
// flag is not a documented answer for a rename's directory entry, and it was
// never one for a create.
//
// Opening a directory with write access and flushing that is the remaining
// candidate. Win32 documents nothing about it, and #228 prices being wrong about
// it precisely: a rare unattributable loss of a device identity if this stays a
// no-op, against a client that cannot generate a key at all on some filesystem
// if an undocumented call is reached for and is wrong. That is why the run comes
// first.
//
// # The state this leaves, said out loud
//
// A WriteDurable caller on Windows gets Write's guarantees and not
// WriteDurable's, and so does a SyncDir one. That is not hypothetical any more
// and it is no longer server-side either — this file used to say "both
// WriteDurable callers are server-side operator tools", which stopped being true
// twice over:
//
//   - clients/fyne's coldstart directory cache reaches WriteDurable through
//     coldstart.SaveCache, on the desktop client;
//   - core/update's floor raise and confirmation marker do too (issue #229), on
//     every peer that can update itself, the client included;
//   - and core/devicestore.LoadOrGenerateKey calls SyncDir on the client's
//     connect path, which is the create case #228 is named for.
//
// None of this is a regression. It is the gap issue #215 closed on Linux and
// could not close here, left open and stated rather than implied.
func syncDirHandle(*os.File) error { return nil }
