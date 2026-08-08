package coldstart

import (
	"github.com/bacchus-vpn/bacchus/core/atomicfile"
)

// writeFileAtomic installs b at path, replacing whatever is there rather than
// rewriting it: a complete file is staged under ".<name>.tmp*" in path's OWN
// directory, flushed, and renamed over the target. The live file is never opened
// for writing, so there is no moment at which path holds a partial file (issue
// #178). It does not create parent directories, so a missing secrets/ directory
// is still an error rather than something a mint quietly conjures.
//
// The shape and every guarantee in it are core/atomicfile's, and that package's
// doc carries the reasoning. This function is what this package's two writers
// call, because the durability choice below is one decision about both of them
// rather than two decisions at two call sites.
//
// # Why this package needs it at all
//
// The secrets file is written by cmd/coldstart-issue, which is
// READ-MODIFY-WRITE: it loads every secret already issued, adds one, and writes
// the whole file back. That inverts the usual stakes of a torn write. Losing an
// update would cost the one secret being added; losing the FILE costs every
// bootstrap secret ever issued, and those are not reconstructible — each is a
// random secret ID and HMAC key that exists in exactly two places, this file and
// a bacchus1: invite that already travelled out of band to a real person
// (docs/design/bootstrap-protocol.md §5). Destroying the server's copy does not
// invalidate those invites in any orderly way; it silently makes every one of
// them unauthenticatable, with no record of what was issued.
//
// The read side is the OPPOSITE polarity from #168's and is the reason this is a
// data-loss card rather than a security one: cmd/coordinator seeds an empty
// store before reloadSecretsLoop's first pass, so an unparseable secrets file
// means nobody can bootstrap. That is fail-closed and noisy, not an admission
// bypass. All of the danger here is on the write side.
//
// And the window is not proportional to the risk. os.WriteFile, which both
// callers used to be, opens the live file with O_TRUNC and refills it; the
// exposure is between the truncate and the bytes landing, and it does not shrink
// as the file grows. A secrets file that gains an entry per issued invite spends
// the same absolute time destroyed-and-not-yet-rewritten on its thousandth write
// as on its first.
//
// # Why both of this package's writers take the DURABLE form
//
// A file's own flush makes the BYTES durable; it does not commit the directory
// entry, so a power loss straight after the rename can restore the previous
// file. Issue #188 ruled that boundary per write rather than per file, and both
// writers here land on the durable side — for different reasons, which is worth
// saying because they are not the same file:
//
//   - The secrets ledger is the accumulated record of what an operator has
//     issued, and nothing rewrites it until the next issue. A lost rename
//     silently drops the most recent secret, after cmd/coldstart-issue has told
//     the operator it was saved — while the invite carrying its other half has
//     already gone to a person.
//   - The client's cached snapshot is the marginal one, and it is included on
//     SaveCache's own argument rather than in spite of it: the fallback from an
//     unusable cache is a network fetch to a coordinator, which for the users
//     this protocol exists for is exactly what may be unreachable at the moment
//     the client launches. Coming back from a power loss holding the PREVIOUS
//     snapshot rather than the one just saved leads to the same place a
//     truncated one does when the older snapshot has expired.
//
// Both are rare, operator- or launch-triggered writes, so the cost is one fsync
// on an operation that already touched the disk once. Nothing in this package is
// on a data path.
func writeFileAtomic(path string, b []byte) error {
	// 0600: this replaces files the previous os.WriteFile named 0600, and the
	// secrets file is staged in the coordinator's secrets directory beside its
	// signing keys.
	return atomicfile.WriteDurable(path, b, 0o600)
}
