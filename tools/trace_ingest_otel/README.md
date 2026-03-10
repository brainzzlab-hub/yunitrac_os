# OTEL JSON Trace Ingest (Trace Contract v1)

Purpose: deterministically convert minimal OpenTelemetry JSON exports into Trace Contract v1 artifacts without storing payload text or PII.

## Inputs
- `--in <path>`: OTEL JSON export (resourceSpans or spans).
- `--out_dir <path>`: under `artifacts/trace_otel/`.
- `--rules <path>`: GDPR regex policy (default `docs/specs/gdpr_default_scrub_rules.json`).

## Behavior
- Parses spans, maps to event types, normalizes payloads, hashes payload only, applies GDPR redaction using enabled-by-default patterns.
- Sorting `(agent_id, step, event_type, span, payload_sha256)` before encoding.
- Outputs (deterministic, no timestamps):
  - `trace_evidence_index.json` (includes `adapter_id="otel_json_v0"`)
  - `canonical_events.bin`
  - `ingest_status.json`
- Stdout: `PASS: otel_trace_ingest` or `FAIL: otel_trace_ingest <SecCode>`.

## SecCodes
`OTEL_BAD_ARGS`, `OTEL_IO_FAIL`, `OTEL_BAD_JSON`, `OTEL_UNSUPPORTED_SPAN`, `OTEL_NONASCII_FIELD`, `OTEL_POLICY_MISSING`, `OTEL_INTERNAL`

## Example
```bash
./scripts/trace_ingest/run_otel_trace_ingest.sh --in fixtures/trace_examples/otel_minimal.json
```
