# coldstart-bootstrap — run a cold-start fetch from an invite (client tool)

Client-side half of the cold-start bootstrap (`old #18`, see
[docs/design/bootstrap-protocol.md](../../docs/design/bootstrap-protocol.md)).
Given an invite string from [`cmd/coldstart-issue`](../coldstart-issue),
performs the authenticated STUN-shaped fetch, verifies the coordinator's
signature, prints the resulting directory snapshot, and optionally caches it.

```sh
go run ./cmd/coldstart-bootstrap -invite "bacchus1:AbCdEf..." -cache snapshot.cache
```

Exit code `0` and a printed snapshot means the fetch, signature check, and
expiry check all passed — this is the same code path
(`core/coldstart.Bootstrap`) a real client embeds directly.

If the endpoint answers but the secret is wrong (or it isn't a bootstrap
endpoint at all), the error is `coldstart: reachable but not authenticated` —
distinguishable from a network-level timeout, which is what a client's
failover logic needs to tell "try a different secret/invite" apart from
"try this endpoint again later."

If the invite carries an admission anchor (issue #60) or a revocation bundle
(issue #69), both are reported to stderr. Pass `-crl-out <path>` to save the
bundle to a file, ready to feed straight into a real client's
`-admission-crl` alongside `-admission-pubkey`.
