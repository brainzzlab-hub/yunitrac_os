# LangChain Hash-Only Callback (Deterministic, No PII)

Purpose: provide a LangChain-compatible callback that records a hash-only action ledger (JSONL) with no payload text, no timestamps, and deterministic ordering suitable for Trace Contract v1 ingestion.

## Ledger format (JSONL)
Each line (one event):
```json
{
  "v": 1,
  "seq": <int>,                      // monotonic from 0
  "event": "tool_start"|"tool_end"|"agent_action"|"final"|"error",
  "agent_id": "<ascii>",             // default "agent0"
  "tool": "<ascii>"|null,
  "input_sha256": "<hex64>"|null,
  "input_len": <int>|null,
  "output_sha256": "<hex64>"|null,
  "output_len": <int>|null,
  "status": "OK"|"FAIL"
}
```
- NO timestamps or wallclock fields.
- Payloads are never stored; only sha256 + length of the stringified payload.
- ASCII-only for `agent_id` and `tool`; any non-ASCII triggers failure in the adapter.
- Deterministic JSON encoding per line: `json.dumps(..., sort_keys=True, separators=(',', ':')) + "\n"`.

## Callback behavior
- Maintains in-memory `seq` counter starting at 0.
- on_tool_start / on_agent_action: hash the tool input (stringify safely), set `input_sha256`/`input_len`, `event` accordingly.
- on_tool_end: hash output, set `output_sha256`/`output_len`, `event=tool_end`.
- on_chain_end / on_agent_finish: emit `final`.
- on_chain_error: emit `error` with `status=FAIL`.
- Ledger path default: `artifacts/control_plane/action_ledger.jsonl`.
- Never prints; no env reads; no randomness.

## Ingestion
- The companion adapter `tools/trace_ingest_langchain/main.py` maps ledger → Trace Contract v1:
  - `tool_start`/`agent_action` → TOOL_CALL
  - `tool_end` → TOOL_RESULT
  - `final` → FINAL
  - `error` → ERROR
  - Payload bytes are empty (hash of empty), status propagated (OK/FAIL).
  - `step = seq`, `agent_id` and `span=tool` (ASCII enforced).
- Run_id: `first16hex( sha256(ledger_sha256 || ":langchain_ledger_v1") )`.

## Determinism & Safety
- No PII, no payload text, no timestamps.
- Stable ordering via `seq`.
- Bounded stdout handled by runner scripts, not the callback itself.
