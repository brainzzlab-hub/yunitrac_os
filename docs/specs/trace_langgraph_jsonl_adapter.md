# LangGraph-style JSONL Adapter (Trace Contract v1)

Purpose: deterministically ingest generic LangGraph/agent JSONL traces into Trace Contract v1 artifacts without retaining payload text or PII.

## Input format
- File is JSONL; each line is a JSON object.
- Expected keys (others ignored):
  - `event_type` (string, required): maps directly to contract event_type (must be in enum).
  - `agent_id` (string, optional): defaults to `"agent0"`.
  - `step` (int, required): must be >= 0.
  - `span` (string, optional): defaults to empty string.
  - `payload` (any, optional): string/array/object/scalar; never stored.
  - `status` (string, optional): defaults to `"OK"`, must be one of OK|FAIL|REDACTED if present.

## Canonicalization
- Normalize payload bytes per Trace Contract v1 rules, then hash and drop the payload.
- ASCII required for `agent_id` and `span`; otherwise fail with `TRACE_NONASCII_FIELD`.
- Unsupported `event_type` → fail with `TRACE_UNSUPPORTED_EVENT`.
- Sorting: after ingestion, events are sorted `(agent_id, step, event_type, span, payload_sha256)` before encoding.

## Scrub / redaction
- Use enabled-by-default categories from `docs/specs/gdpr_default_scrub_rules.json`.
- If any pattern matches payload text, set `status="REDACTED"`, zero the payload bytes, and hash empty.
- Category hit counts are accumulated by category id; no matched text is stored.

## Outputs
- `trace_evidence_index.json` (hashes + counts only)
- `canonical_events.bin` (binary, see Trace Contract v1)
- `ingest_status.json` (status + seccode only)

## Determinism / safety
- No timestamps or environment data in outputs.
- No payload text or PII leaves the adapter.
- Evidence mapping only; not legal advice.
