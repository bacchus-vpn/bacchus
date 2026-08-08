package atomicfile

import "os"

// syncDirHandle is a documented no-op on Windows, and the honest reason is that
// Windows has no directory-fsync primitive to call: FlushFileBuffers wants a
// handle opened for writing, and a directory handle is never one. Returning the
// ERROR_ACCESS_DENIED it produces would fail every WriteDurable on this
// platform for a reason the caller cannot act on.
//
// The property is not unavailable here, only unreachable through this call.
// Windows expresses it at the rename instead — MoveFileEx with
// MOVEFILE_WRITE_THROUGH — which os.Rename does not pass and which this package
// would have to reach syscall for.
//
// A caller that runs here HAS now appeared, and it is not a WriteDurable one.
// Issue #215 gave the three ed25519 seed writers a SyncDir on the key's
// directory, and one of them — core/devicestore.LoadOrGenerateKey — is on the
// client's connect path and therefore on Windows. So the create case this
// package documents as the worse polarity is durable on Linux and is not here,
// which is issue #228. The two WriteDurable callers remain server-side operator
// tools (cmd/admission-issue's revocation list, cmd/coldstart-issue's secrets
// ledger) that run on the coordinator host.
//
// #228 also holds the question this file cannot answer by itself: MoveFileEx
// covers a rename and a first-run create is not one, and whether NTFS needs a
// separate step at all — it journals directory-index changes — is something to
// establish rather than assume.
func syncDirHandle(*os.File) error { return nil }
