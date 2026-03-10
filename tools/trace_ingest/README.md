# Trace Ingest (LangGraph JSONL Adapter)

Purpose: deterministically convert LangGraph-style JSONL traces into Trace Contract v1 artifacts without storing payload text or PII.

## Inputs
- `--in <path>`: JSONL trace file.
- `--out_dir <path>`: output directory under `artifacts/trace/`.
- `--rules <path>`: PII regex policy (default `docs/specs/gdpr_default_scrub_rules.json`).

## Behavior
- Parses JSONL, filters to contract fields, normalizes payload bytes, hashes payload, drops text.
- Scrub: if any enabled-by-default GDPR regex matches payload text, mark event `REDACTED`, zero payload bytes, hash empty, and increment category counts.
- Sorting: events sorted `(agent_id, step, event_type, span, payload_sha256)` before encoding.
- Outputs (all deterministic, no timestamps):
  - `trace_evidence_index.json`
  - `canonical_events.bin`
  - `ingest_status.json`
- Stdout: single line `PASS: trace_ingest` or `FAIL: trace_ingest <SecCode>`.

## SecCodes
- `TRACE_BAD_ARGS`, `TRACE_IO_FAIL`, `TRACE_BAD_JSON`, `TRACE_UNSUPPORTED_EVENT`, `TRACE_NONASCII_FIELD`, `TRACE_POLICY_MISSING`, `TRACE_INTERNAL`

## Run
```bash
./scripts/trace_ingest/run_trace_ingest.sh --in fixtures/trace_examples/langgraph_minimal.jsonl
```
