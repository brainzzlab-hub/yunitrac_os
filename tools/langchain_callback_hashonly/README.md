# LangChain Hash-Only Callback

Purpose: record a deterministic, PII-free JSONL ledger of LangChain events (hash + length only, no payload text, no timestamps).

Usage:
- Import `YuniTrackCallbackHashOnly` and attach to your LangChain agent/chain.
- Defaults:
  - `ledger_path="artifacts/control_plane/action_ledger.jsonl"`
  - `agent_id="agent0"`

Guarantees:
- Each event JSON is written with `sort_keys=True, separators=(',',':')`, newline-terminated.
- seq starts at 0 and increments per event.
- Input/output content is never stored; only sha256 + byte length.
- ASCII-only agent_id/tool enforced (non-ASCII -> no record; adapter will fail if present).
- No wallclock/time fields; deterministic ordering.

SecCodes (adapter/runner):
- Callback I/O failure: `LCH_CB_IO_FAIL`
- Non-ASCII agent/tool: `LCH_CB_NONASCII`

See `docs/specs/langchain_hashonly_callback.md` for ledger schema.
