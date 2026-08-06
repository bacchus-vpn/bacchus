# coldstart-issue — mint a per-user cold-start secret (operator tool)

Operator-side half of the cold-start bootstrap (`old #18`, see
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

## One issuer at a time, and the file is written whole

This tool is read-modify-write: it loads every secret already issued, adds the
new one, and writes all of them back. Two things follow from that, both closed
by issue #178, and neither is visible in normal use.

**The file is installed, not rewritten.** A complete copy is staged beside it as
`.<name>.tmp*` and renamed into place, so a run killed mid-mint cannot leave a
truncated file. That matters more here than the usual "a reader might catch half
a file": a truncated secrets file has not lost the entry being added, it has lost
*every secret ever issued* — each of which exists only in this file and in a
`bacchus1:` invite already in somebody's hands. A killed run can leave a `.tmp`
file behind; it is inert and safe to delete.

**Only one issuer may write a given secrets file at a time.** A `<secrets
path>.lock` is created for the duration of the mint and removed afterwards, and a
second issuer refuses rather than racing. Two concurrent runs would each write a
complete, well-formed file and the second would land without the first's secret —
an invite already printed that will simply never work, with nothing anywhere to
show that it went missing.

A run that is *killed* leaves its lock behind, since nothing releases it on the
way out. The next run says so and names the file:

```
another coldstart-issue is writing the secrets file (…/bootstrap-secrets.json.lock exists)
```

If no other issuer is running, delete that file and run again.

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
