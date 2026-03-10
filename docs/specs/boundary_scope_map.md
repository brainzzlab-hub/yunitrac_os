# Boundary Scope Map (deterministic, canon-aligned)

## Canon boundary set (enterprise profile)
- Source of truth: `scripts/gate_boundary_deps.sh`, `scripts/guardrails/forbidden_deps_symbols_scan.sh`.
- Boundary crates (must remain exactly this set unless canon changes):
  - `secure_runner`
  - `dio_core`
- Rule: only these crates are treated as in-boundary for dependency/symbol forbids.

## secure_ingress position
- `secure_ingress` is **out of boundary** under current gate definitions.
- Evidence: boundary arrays in gate scripts exclude `secure_ingress`.

## Applicable canon clauses for boundary crates
- I1 Secure boundary restrictions (no time/net/fs/rng/concurrency)
- I2 Determinism (byte-identical outputs)
- I3 No feedback to actor
- I4 Exit allowlist
- I5 GDPR separation

## Enforcement mechanism
- Dependency/symbol guards: `scripts/gate_boundary_deps.sh`, `scripts/guardrails/forbidden_deps_symbols_scan.sh`.
- Boundary scope enforcement guardrail: `scripts/guardrails/boundary_scope_enforce.sh` (fail-closed if boundary list drifts or `secure_ingress` enters boundary).

## Guarantee
- Proof pipelines run the boundary scope guardrail to ensure the boundary set stays frozen and `secure_ingress` remains outside unless canon is updated explicitly.
