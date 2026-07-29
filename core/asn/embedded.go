package asn

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"sync"
)

// embeddedGz is the IP→AS table this binary ships with, gzipped.
//
// ADR-0044's first amendment ruled the distribution question §6 left open: the table
// is embedded in the client build, refreshed per release, and COMMITTED rather than
// fetched at build time — because a build that fetches is not reproducible, and the
// signed release channel (#34) and code signing (#38) both rest on a reviewer being
// able to check that a published binary corresponds to published source.
//
// # Why gzipped text and not a packed binary
//
// The second amendment measured it. §6's headline "~1.4 MB compressed" is a
// delta-varint binary form, and adopting it would have put a custom decoder in front
// of a parser that decides a security control — reversing this package's stated
// reason for being text at all ("it needs no decoder, the whole parse is auditable
// in one screen"). Gzipped text costs 3.14 MB against that 1.38 MB. The extra
// ~1.75 MB buys keeping the only decoder in the path a standard-library one, and the
// whole format still readable with `gunzip -c`. That is the trade the amendment
// records, on measured numbers rather than an assumption.
//
// Note what is NOT here: no fetch, no path, no configuration. This package still
// cannot make a network call, and embedding does not change that — the bytes are in
// the binary's read-only data before it starts.
//
//go:embed table.tsv.gz
var embeddedGz []byte

// embeddedOnce parses the embedded table at most once per process.
//
// Once matters more than it looks. The table is ~700k rows and costs roughly 190 ms
// and ~28 MB to parse, and core/relaychain.go's directory RELOADS on an interval
// (reloadRelayDirLoop, issue #27) — every reload calls loadRelayDirectory, which
// asks for this table. Re-parsing on each would spend that cost repeatedly, forever,
// for a result that cannot have changed: the bytes are compiled in.
//
// Lazily, too, not at init. Only a chaining or forwarding node ever builds a relay
// directory, so a node that does neither should not pay the parse or carry the heap
// — which is most nodes, and every client that has chaining switched off.
var embeddedOnce = sync.OnceValues(readEmbedded)

// Embedded returns the table compiled into this binary.
//
// It is the client-side answer to issue #23. Until it existed, `relayDirectory.as`
// was nil on every build, every hop resolved to unknown, and the AS-diversity ladder
// degraded through pass 2 to exactly the chain it built before the control was
// written — the seam was in place and both consumers used it, and what was missing
// was bytes on a client.
//
// The returned *Table is shared, and that is safe for the reason Table documents:
// nothing mutates after parsing, so any number of chain builds can read it at once
// without a lock. Callers must not assume they own it.
//
// An error here means the committed table is not loadable — a build-time fault, not
// a runtime condition, since the bytes cannot change between build and run.
// TestEmbeddedTableLoads is what catches it, in CI, before a release carries it.
func Embedded() (*Table, error) { return embeddedOnce() }

func readEmbedded() (*Table, error) {
	zr, err := gzip.NewReader(bytes.NewReader(embeddedGz))
	if err != nil {
		return nil, fmt.Errorf("asn: embedded table: %w", err)
	}
	defer zr.Close()
	t, err := Read(zr)
	if err != nil {
		return nil, fmt.Errorf("asn: embedded table: %w", err)
	}
	return t, nil
}
