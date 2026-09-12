# ADR 0001 — optional external enforcement

## Status

Accepted.

## Context

Privacy Shield must make its privacy decision and write its local audit record
without importing a governance runtime. A deployment may still need to attach
an enforcing host that returns a verdict and a signed receipt.

## Decision

The package exposes one neutral seam:

- `EnforcementDecision` is the local decision already made by the guard.
- `EnforcementVerdict` carries `permit`, `hold`, or `deny`, an optional
  structural gate verdict, an optional receipt identifier, and obligations.
- `EnforcementSink` defines `record_decision()` and `gate()`.
- `NoOpEnforcementSink` is the default and leaves the local decision unchanged.
- `ExternalEnforcementAdapter` is an interface-only stub. A consuming host owns
  the real adapter outside this repository.

`gate(..., enforce=False)` is an advisory preview and must remain read-only.
`gate(..., enforce=True)` may append a signed receipt and return its identifier.
The host verdict enriches the record; it cannot turn a locally blocked egress
into an allowed one.

## Consequences

The base package has no host dependency. Imports remain side-effect free. The
runner and CLI use the no-op default. Deployments add enforcement by dependency
injection without changing the scanner, overlay, or local audit path.

The executable contract is
`tests/test_privacy_gate_external_enforcement.py`: standalone blocking and
allowing remain complete, an attached sink receives the same decision, and a
faulty sink cannot break the core guard.
