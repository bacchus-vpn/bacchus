# bacchus fork of github.com/pion/dtls/v3

Vendored from upstream `v3.1.4` via `go.mod`'s
`replace github.com/pion/dtls/v3 => ./third_party/pion-dtls`.

Only the packages bacchus actually imports are present (computed with
`go list -deps ./...` from the module root — build and test dependencies are
identical, so this set covers both), non-test `.go` files only. Everything
copied is byte-identical to upstream except the one patch below; `LICENSE` and
`LICENSES/` are carried unmodified (MIT).

## Patch: `pkg/protocol/handshake/random.go` (issue #57)

Upstream's `Random.Populate()` sets `GMTUnixTime = time.Now()`, and
`MarshalFixed` writes it into the first 4 bytes of the 32-byte handshake
`Random` sent in both the ClientHello and the ServerHello. Real browsers fill
all 32 bytes randomly, so a real Unix timestamp there is a wall-clock-
correlated distinguisher.

This can't be fixed from outside the module (e.g. via a
`SetDTLSClientHelloMessageHook` rewrite, as bacchus already does for the
cipher/extension shape — see `docs/adr/0018` in the main repo): pion hashes
`state.localRandom` directly into the master-secret PRF, independent of
whatever a hook returns for the wire message. Patching only the wire bytes
would desync the two peers' PRF inputs and break the handshake. The fix has to
make `state.localRandom` itself carry no timestamp, which means patching
`Populate()`.

`Populate()` now fills all 32 bytes with `crypto/rand` and derives
`GMTUnixTime` from the first 4 of them (rather than the real clock), leaving
`RandomBytes` as the trailing 28. The `GMTUnixTime time.Time` /
`RandomBytes [28]byte` struct shape, `MarshalFixed`, and `UnmarshalFixed` are
all unchanged from upstream — every existing caller keeps working, and the
diff is one function.

## Verification: byte-diff against upstream v3.1.4 (issue #86)

Confirmed 2026-07-10 by cloning upstream `pion/dtls` at tag `v3.1.4`
(`e4aad60b48a4f5619443902fb484053f53c4759b`) and comparing every file in this
directory (except this file, which is bacchus-authored, not vendored) against
the matching path in upstream's git tree — 136 files: 131 `.go` files plus
`LICENSE`, `LICENSES/CC0-1.0.txt`, `LICENSES/MIT.txt`, `go.mod`, `go.sum`.

The comparison read both sides at the git blob level (`git cat-file`/`git
show`), not the checked-out working tree: a naive working-tree diff of a fresh
upstream clone flagged all 136 files as different, which turned out to be a
false positive from the clone's local `core.autocrlf` rewriting every text
file to CRLF on checkout, while this repository's `.gitattributes` normalizes
everything to LF. Reading git's stored blob content on both sides bypasses
that local checkout-time rewriting entirely.

Result: exactly one file differs — `pkg/protocol/handshake/random.go` — and
its diff is precisely the `Populate()` patch described above (same fields
touched, same approach, same doc comment already present here explaining it).
Every other file (130 other `.go` files, `LICENSE`, both `LICENSES/*` texts,
`go.mod`, `go.sum`) is byte-identical to upstream, and nothing vendored here
was missing from upstream's tree at that tag. This confirms the "byte-identical
except the one patch" claim above is exact, not just believed.

## Re-syncing on a pion/dtls version bump

1. Recompute the needed package set: `go list -deps ./...` from the bacchus
   module root, filtered to `github.com/pion/dtls/v3...`.
2. Copy the non-test `.go` files for that package set (plus `LICENSE`,
   `LICENSES/`, `go.mod`) from the new version into this directory, replacing
   everything here.
3. Re-apply the `Populate()` patch above (diff this directory's git history
   against the previous vendor commit to see the exact prior patch).
4. Update the version note at the top of this file.

Consider upstreaming the fix instead — pion has taken fingerprint-adjacent
patches before, and it removes the need for this fork entirely.
