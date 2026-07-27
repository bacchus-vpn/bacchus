# 7. Documentation is part of "Done"

- Status: accepted
- Date: 2026-07-02

## Context

Documentation that lags the code rots. We want docs to land with the change they
describe, not later.

## Decision

A change is not "Done" until its documentation ships **in the same PR** — README,
runbook, ADR, or inline docs as appropriate.

## Consequences

- Reviewers check for docs as part of review.
- No separate "update the docs" backlog forms behind the code.
