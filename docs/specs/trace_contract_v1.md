# Trace Contract v1 (deterministic, PII-safe, tools-only)

Purpose: define a portable, deterministic event representation for agent traces that can be ingested outside the secure boundary without storing payload text or PII.

## Event schema (canonical form)
```json
{
  "v": 1,
  "event_type": "LLM_CALL" | "TOOL_CALL" | "TOOL_RESULT" | "HITL_REQUEST" | "HITL_DECISION" | "STATE" | "ERROR" | "FINAL",
  "agent_id": "<string>",          // default "agent0" if missing
  "step": <int>,                   // required, >= 0
  "span": "<string>",              // optional, default ""
  "payload_sha256": "<hex64>",     // sha256 of normalized payload bytes (payload NOT stored)
  "payload_len": <int>,            // length of normalized payload bytes
  "status": "OK" | "FAIL" | "REDACTED"
}
```

## Canonicalization rules
- Accept arbitrary input JSON fields; extract only the schema fields.
- Normalize payload bytes:
  - string payload → UTF‑8, CRLF→LF, rstrip whitespace.
  - object/array payload → `json.dumps(sort_keys=True, separators=(',',':'))` UTF‑8 bytes.
  - null / missing / other scalars → empty bytes.
- Hash only normalized payload bytes. Payload text is never stored.
- Sorting: canonical event list sorted by `(agent_id, step, event_type, span, payload_sha256)`.
- Fields `agent_id` and `span` must be ASCII; otherwise fail closed.
- Unsupported `event_type` → fail closed.

## Scrub / PII redaction
- Use `docs/specs/gdpr_default_scrub_rules.json` (enabled_by_default categories only).
- If any enabled pattern matches the payload text, mark the event `status="REDACTED"`, replace payload bytes with `b""` (hash of empty), `payload_len=0`, and increment category counts. No matched text is retained.

## Outputs (artifact contract)
Under `artifacts/trace/<run_id>/`:
- `trace_evidence_index.json`: hash-only summary with event counts and PII category counts.
- `canonical_events.bin`: binary encoding (see adapter spec).
- `ingest_status.json`: `{"status":"PASS|FAIL","seccode":"..."}` label/count only.

## Determinism
- No timestamps. Stable ordering and JSON encoding (sort_keys + compact separators).
- `run_id = first16hex( sha256(input_trace_sha256 || ":" || rules_version) )`.
- Same inputs ⇒ identical bytes/hashes.

## Safety / legal
- Evidence mapping only; not legal advice.
- No PII or payload text is stored in artifacts.
