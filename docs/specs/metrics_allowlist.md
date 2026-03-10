# Metrics Allowlist (yunitrack_os)

## Allowed metrics (names + meaning)
- `M001` — frames_ingested (count of frames), integer, range 0..=1_000_000, step 1, max 1 update per run.
- `M002` — bytes_ingested (total bytes), integer, range 0..=100_000_000, step 16, max 1 update per run.
- `M003` — policy_violations (count), integer, range 0..=10_000, step 1, max 10 updates per run.

Only these metrics are permitted. Any other metric id MUST be rejected.

## Labels
- No labels allowed. High-cardinality or free-form labels are forbidden.

## Value constraints
- Integer only (no floats, no strings).
- Must be within the declared range.
- Must align to the declared quantization step.
- Update rate per metric must not exceed the declared max_updates_per_run.

## Forbidden content (anti–covert channel)
- No payload-derived strings, hashes, IDs, file paths, error reasons, schema/validator details, signatures/keys, hints, or debug text.
- Metrics outputs must be numeric-only and content-free.

## Enforcement
- Runtime validator enforces whitelist/bounds/step/update-rate.
- Proof gates (prove_enterprise.sh, prove_lite.sh) call `scripts/guardrails/metrics_scan.sh` to fail closed on:
  - Forbidden keywords in metric artifacts.
  - Label-like patterns.
  - Non-numeric values in key=value lines.
