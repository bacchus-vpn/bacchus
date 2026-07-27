# bacchus fork of github.com/refraction-networking/utls

Vendored from upstream `v1.8.2` via `go.mod`'s
`replace github.com/refraction-networking/utls => ./third_party/utls`.

Only the packages bacchus actually imports are present (computed with
`go list -deps ./...` from the module root — build and test dependencies are
identical, so this set covers both), non-test `.go` files only. Everything
copied is byte-identical to upstream except the two patches below (one
behavioral, one gofmt-only); `LICENSE` (root and `dicttls/`) is carried
unmodified (BSD-style, Go Authors).

## Patch: `common.go` + `handshake_client_tls13.go` (issue #92)

The reality transport authenticates a client to the exit *inside the
ClientHello* (ADR-0032) and now presents the impersonated origin's actual
certificate bytes on the terminate path, rather than a leaf that merely
copies the origin's fields. The exit does not hold the origin's private key,
so it cannot produce a `CertificateVerify` signature that validates under the
stolen certificate's public key — it can only sign with its own key.

Upstream `readServerCertificate` (`handshake_client_tls13.go`) verifies that
signature unconditionally:

```go
if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
	sigHash, signed, certVerify.signature); err != nil {
	c.sendAlert(alertDecryptError)
	return errors.New("tls: invalid signature by the server certificate: " + err.Error())
}
```

There is no existing config hook for this: `InsecureSkipVerify` (and uTLS's
own `InsecureSkipTimeVerify` / `InsecureServerNameToVerify`) only gate
`verifyServerCertificate` — chain-of-trust and hostname checks, called
*before* this — never the `CertificateVerify` signature itself. That check is
what proves the peer holds *some* private key at all; it is independent of,
and stronger than, chain/hostname verification.

Skipping it is safe here only because trust for this transport already comes
from elsewhere: the Noise end-to-end handshake carried inside the TLS session
(ADR-0009) and the ClientHello-embedded ECDH authenticator (ADR-0032). The
outer TLS layer is camouflage, not the security boundary, so a client that
already knows (by construction — it dialed this exit using its known static
public key from the answer) it's talking to a real Bacchus exit does not need
the exit to also hold the impersonated site's private key.

The patch adds one new field, following uTLS's own `Insecure*` naming
convention (`common.go`, next to `InsecureServerNameToVerify`):

```go
// InsecureSkipCertVerifySignature controls whether a TLS 1.3 client verifies
// the server's CertificateVerify signature against the leaf certificate's
// public key. ...
InsecureSkipCertVerifySignature bool // [uTLS] [bacchus]
```

and gates only the failure branch of the one call site above — the check
still runs unconditionally, so a signature that *does* verify is never
treated differently; only a verification failure is tolerated when the flag
is set:

```go
if err := verifyHandshakeSignature(...); err != nil && !c.config.InsecureSkipCertVerifySignature {
	c.sendAlert(alertDecryptError)
	return errors.New(...)
}
```

Also added to `Config.Clone()`'s field list, matching the three neighboring
`Insecure*` fields already there.

**Scope discipline:** this field defaults to `false` everywhere, including
upstream's own zero value. It is set to `true` in exactly one place in the
whole bacchus codebase — `realityClientHandshake` in
`core/transport_reality.go`, the authenticated reality client dial. It must
never be set anywhere else; doing so would turn a narrowly-justified
protocol-specific tolerance into a general TLS downgrade.

The TLS 1.2 client path (`handshake_client.go`) has its own, separate
signature-verification code and is intentionally **not** patched: uTLS always
negotiates TLS 1.3 for the Chrome fingerprint profile the reality client
uses, so that path is never exercised here and patching it would only widen
the diff against upstream for no behavioral gain.

## Patch: `u_roller.go` (gofmt only, no behavior change)

This repo's CI runs `gofmt -l .` across the whole tree with no `third_party/`
exclusion (`.github/workflows/ci.yml`), and `third_party/pion-dtls` happened to
already be clean under it. Upstream utls's `u_roller.go` is not: its `Dial` doc
comment has an indented example block without the blank comment line gofmt's
doc-comment reformatter (Go 1.19+) requires to recognize it as preformatted, so
`gofmt -l` flags it even though the file is otherwise untouched.

Rather than exclude `third_party/` from the CI gate — a repo-wide policy change
this vendor bump doesn't need — `gofmt -w` was run on this one file. The diff is
two comment lines (a blank `//` inserted before the example block); nothing
executable changed. This is the one exception to "everything is byte-identical
to upstream except the documented patch" above; re-syncing should re-apply it
the same way (`gofmt -l third_party/utls/` after copying will point at whatever
file, if any, needs it under the Go version in use at the time).

## Re-syncing on a utls version bump

1. Recompute the needed package set: `go list -deps ./...` from the bacchus
   module root, filtered to `github.com/refraction-networking/utls...`.
2. Copy the non-test `.go` files for that package set (plus `LICENSE`,
   `README.md`, `go.mod`, and `dicttls/LICENSE` + `dicttls/README.md`) from
   the new version into this directory, replacing everything here. Vendored
   files inherit the Go module cache's read-only permission bit — clear it
   (`chmod -R u+w` / equivalent) before editing.
3. Re-apply the two-part patch above (diff this directory's git history
   against the previous vendor commit to see the exact prior patch).
4. Update the version note at the top of this file.

Consider upstreaming the fix instead — this is exactly the kind of hook the
REALITY-style protocols (Xray/VLESS) already special-case in their own uTLS
forks, so upstream refraction-networking may be receptive to a config-gated
version of it.
