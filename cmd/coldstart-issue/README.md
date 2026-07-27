# coldstart-issue — mint a per-user cold-start secret (operator tool)

Operator-side half of the cold-start bootstrap (issue #18, see
[docs/design/bootstrap-protocol.md](../../docs/design/bootstrap-protocol.md)).
Mints a fresh per-user secret, appends it to the coordinator's secrets file,
and prints an invite string to hand the new user out of band.

```sh
go run ./cmd/coldstart-issue \
  -secrets /etc/bacchus/bacchus-bootstrap-secrets.json \
  -coordinator YOUR_COORDINATOR_HOST:3478 \
  -pubkey <hex — logged by cmd/coordinator on first run>
```

The secrets file is picked up by a *running* coordinator within 30s — no
restart needed (`cmd/coordinator`'s `-bootstrap-secrets` reload loop). If the
file doesn't exist yet this tool creates it.

The invite printed to stdout looks like `bacchus1:AbCdEf...` — hand it to the
recipient over a channel the app itself doesn't control (messenger, QR code
in person). It is not signed; see the design doc for why that's fine here.

Add `-admission-pubkey <hex>` to embed the admission anchor (issue #60) so the
recipient verifies exits end-to-end with no extra setup — this mints a v2
invite instead of v1. Add `-admission-crl <path>` (a signed bundle from
`cmd/admission-issue -crl`, issue #69) to also embed a revocation bundle
alongside the anchor — this mints a v3 invite; requires `-admission-pubkey`,
since the bundle is verified against that same anchor. The bundle is checked
at mint time — signature, anchor match, *and* expiry (issue #90) — so a stale
or otherwise-bad `-admission-crl` file fails loudly here rather than shipping
a broken invite. Re-run this whenever the bundle needs refreshing (it is
short-lived by design); a recipient's own client re-reads a bundle it was
handed via `-admission-crl <path>` on an interval, so redistributing a
refreshed file is enough — no client restart needed.

Feed it to [`cmd/coldstart-bootstrap`](../coldstart-bootstrap) to test it, or
to a real client's cold-start flow (`core/coldstart.Bootstrap`).
