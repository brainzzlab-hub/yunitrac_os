# LangChain Ledger Ingest (Trace Contract v1)

Purpose: convert a hash-only LangChain ledger JSONL into Trace Contract v1 artifacts, with no payload text and deterministic encoding.

Input ledger format: see `docs/specs/langchain_hashonly_callback.md`.

Output (under `artifacts/trace_langchain/<run_id>/`):
- `trace_evidence_index.json` (hashes + counts, `adapter_id="langchain_ledger_v1"`)
- `canonical_events.bin`
- `ingest_status.json`

Run:
```bash
./scripts/trace_ingest/run_langchain_ledger_ingest.sh --in artifacts/control_plane/action_ledger.jsonl
```

Stdout (bounded):
- PASS: `PASS: langchain_trace_ingest`
- FAIL: `FAIL: langchain_trace_ingest <SecCode>`
