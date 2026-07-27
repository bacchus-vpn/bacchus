# Security Policy

Bacchus is a censorship-circumvention tool; bugs can put real people at risk.
Please report vulnerabilities **privately**.

## Reporting a vulnerability

Contact the maintainers privately (security contact **TBD** — to be published
before the repository goes public). Do **not** open a public issue for security
problems.

Please include: a description, the affected component, reproduction steps, and
impact. We aim to acknowledge quickly and to coordinate a fix and disclosure
timeline with you.

## Principles

- **No secrets in the repository.** Endpoints and credentials load from local
  config / env files (gitignored); only `*.example` templates are tracked. If you
  spot a committed secret or real infrastructure IP, report it as a vulnerability.
- **Minimal logging is a safety feature.** Nodes must not log client IPs,
  destinations, or anything correlating a user to their traffic. Default logs are
  counts/states only; verbose logging is opt-in and must never capture
  user-identifying data.
- **Relays forward, exits egress.** Roles are separated so a forwarding node
  carries the least possible knowledge about users.
- **Least data.** Collect nothing you don't need; retain nothing you don't must.
