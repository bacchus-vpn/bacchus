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
// would have to reach syscall for. Nothing needs it yet: both WriteDurable
// callers are server-side operator tools (cmd/admission-issue's revocation
// list, cmd/coldstart-issue's secrets ledger) that run on the coordinator host.
// A Windows caller of WriteDurable would get Write's guarantees and not
// WriteDurable's, so the first one to appear is the card that fixes this.
func syncDirHandle(*os.File) error { return nil }
