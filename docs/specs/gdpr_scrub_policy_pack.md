# GDPR Scrub Policy Pack (enterprise-ready, fail-closed)

## Threat model
- Risk: PII/PHI or other GDPR-controlled data leaking via artifacts/logs/outputs.
- Channels: text artifacts (reports, manifests, commands logs), metrics/audit/security streams.
- Response: fail-closed; on detection, emit a single bounded SECURITY line; no payload echo.

## Modes
- DEFAULT: deterministic seeded rules from regex example ZIP (see provenance). Enabled by default for unattended runs.
- CUSTOM: user-supplied rule set; empty by default, must be explicitly provided.
- HITL: human-in-the-loop rules; disabled by default. When enabled, findings require operator approval markers before failing proofs.

## QuickNames heuristic (opt-in, OFF by default)
- Conservative name-like regex list; high false-positive risk on labels/titles. Stay OFF unless an operator explicitly enables HITL review.

## Determinism rules
- Stable ordering of rules; fixed JSON schema; sorted keys/compact separators in outputs.
- Findings artifact: `artifacts/security/gdpr_findings.json` with label + count only (no snippets, no file paths outside workspace).
- Exit behavior: exit code 0 on clean scan; non-zero on detection or scan error. Failure output limited to a single SECURITY line.
- SecCode mapping: failures map to a bounded SecCode; no verbose reasons to actor outputs.

## Interface contracts
- Inputs: workspace root plus `artifacts/` subtree only; optional request ledger under `artifacts/ops/`.
- Outputs: `artifacts/security/gdpr_findings.json`; bounded SECURITY line on failure; no network/telemetry; no temp files outside workspace.
- Guardrail script: read-only; must not mutate inputs; deterministic given the same inputs.

## Provenance
- Rules are derived solely from the regex example ZIP contents listed in `docs/specs/regex_example_zip_contents.tsv`.
- ZIP used: `docs/specs/regex_examples.zip`

## Failure handling
- Malformed inputs => fail-closed with SECURITY line; findings file omitted.
- Missing inputs => produce empty findings with PASS.
