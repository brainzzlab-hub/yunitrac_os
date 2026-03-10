# OpenTelemetry JSON Adapter (Trace Contract v1)

Purpose: deterministically ingest minimal OpenTelemetry (OTEL) trace exports into Trace Contract v1 without storing payload text or PII. Evidence mapping only; not legal advice.

## Accepted input shapes
- JSON object containing either:
  - `{"resourceSpans":[ ... ]}` (OTLP/JSON-like), or
  - `{"spans":[ ... ]}` (flattened export).
- Each span must contain:
  - `name` (string, required)
  - `spanId` (hex string) or `id` (string) for ordering
  - `attributes` (object or list of key/value entries)
Missing/unsupported structures → fail closed (`OTEL_BAD_JSON`).

## Mapping to Trace Contract v1
- `event_type`:
  - `TOOL_CALL` if span name contains "tool" or attributes include `gen_ai.tool.name`
  - `LLM_CALL` if span name contains "llm" or attributes include `gen_ai.model` or `gen_ai.request.model`
  - `HITL_REQUEST` if span name contains "hitl"
  - `FINAL` if span name contains "final"
  - `ERROR` if span status indicates error
  - else `STATE`
- `agent_id`: attribute `agent.id` else `"agent0"` (ASCII required).
- `step`: integer attribute `step` else 0 (>=0).
- `span`: first 8 chars of `spanId/id` (ASCII required).
- `status`: defaults to `OK`; set to `REDACTED` if scrub triggers; `ERROR` spans map to status `FAIL`.
- `payload` source (first present): `gen_ai.prompt` → `gen_ai.request` → `input` → `output` → empty.
- Payload normalization and hashing follow Trace Contract v1 (CRLF→LF for strings; JSON canonical for objects; hash only; never stored).

## Scrub / PII redaction
- Use enabled-by-default categories from `docs/specs/gdpr_default_scrub_rules.json`.
- If any pattern matches payload text, mark event `status="REDACTED"`, zero payload bytes before hashing, and increment category counts. No matched text is retained.

## Sorting and encoding
- Canonical event list sorted by `(agent_id, step, event_type, span, payload_sha256)`.
- Binary encoding identical to Trace Contract v1 (`canonical_events.bin`).

## Outputs (deterministic, no timestamps)
Under `artifacts/trace_otel/<run_id>/`:
- `trace_evidence_index.json` (hashes + counts only, includes `adapter_id="otel_json_v0"`).
- `canonical_events.bin`
- `ingest_status.json` (`{"status":"PASS|FAIL","seccode":"..."}`).

## Determinism
- `run_id = first16hex( sha256(input_trace_sha256 || ":" || "otel_json_v0" || ":" || rules_version) )`.
- Stable ordering; JSON written with `sort_keys=True`, compact separators; no wallclock fields.

## Fail-closed SecCodes
- `OTEL_BAD_ARGS`, `OTEL_IO_FAIL`, `OTEL_BAD_JSON`, `OTEL_UNSUPPORTED_SPAN`, `OTEL_NONASCII_FIELD`, `OTEL_POLICY_MISSING`, `OTEL_INTERNAL`.
