# LLM Bridge Mode (Outside Boundary)

## Purpose
Provide an opt-in, offline-by-default bridge that can produce deterministic proposal bytes outside the secure boundary. It never alters boundary/runtime crates and never stores task text or model output.

## Threat model
- Task files may contain PII; they are read outside boundary only and never persisted beyond hash/length.
- Model output (if forwarding enabled) is never stored; only SHA256 and length are recorded.
- Default `provider=none` and `forward=0` performs a pure dry-run with empty payload.
- No timestamps or randomness are written to artifacts.

## Determinism contract
- Given identical inputs, outputs are byte-identical.
- proposal.bin structure is fixed; JSON artifacts use sorted keys and compact separators.
- No wallclock use; no random IDs; file ordering sorted LC_ALL=C.

## Inputs (CLI flags only)
- `--mode ANALYZE|GENERATE|COMMUNICATE|MOVEMENT`
- `--canon_hash_hex`, `--tick_hash_hex` (64 hex chars each)
- `--tick` (u64)
- `--sliders s1,s2,s3,s4` (0..100, step=2)
- `--task_file <path>` (optional, read-only; not persisted)
- `--out_dir artifacts/llm_bridge/<run_id>/` (required)
- `--provider none|openai|anthropic|local` (default none)
- `--forward 0|1` (default 0; must be 1 to contact provider)
- `--max_bytes <int>` (default 4096; hard cap on normalized payload)

## Outputs (deterministic)
- `proposal.bin` (binary as below)
- `proposal_manifest.json` (hashes, sizes, labels only)
- `provider_status.json` (provider, forward, status)
- `audit_stub.json` (content-free hashes/codes)

### proposal.bin layout
```
[mode_byte:1]  ANALYZE=0, GENERATE=1, COMMUNICATE=2, MOVEMENT=3
[tick_le:8]    little-endian u64
[s1:1][s2:1][s3:1][s4:1]   each 0..255
[canon_hash:32]            raw bytes from hex
[tick_hash:32]             raw bytes from hex
[payload_sha256:32]        SHA256(normalized_payload_bytes)
```

`normalized_payload_bytes`:
- provider=none OR forward=0 → empty bytes
- provider!=none AND forward=1 → normalized model output:
  - UTF-8 bytes
  - CRLF -> LF, trim trailing whitespace
  - truncate to `--max_bytes`
  - **not stored**, only hashed

## Failure handling (bounded)
Stdout on failure: `FAIL: llm_bridge_mode <SecCode>`
SecCodes:
- BRIDGE_BAD_ARGS
- BRIDGE_BAD_HEX
- BRIDGE_BAD_SLIDERS
- BRIDGE_IO_FAIL
- BRIDGE_TOOL_MISSING
- BRIDGE_PROVIDER_DISABLED
- BRIDGE_PROVIDER_FAIL

## Integration points
- proposal.bin is suitable for future ingestion outside boundary; ingestion is NOT implemented here.
- Artifacts live under `artifacts/llm_bridge/<run_id>/` and are deterministic.

## Operator safety
- Offline by default: provider calls only when `--forward=1` and `--provider!=none`.
- If provider tooling is absent, tool fails closed with `BRIDGE_TOOL_MISSING`.
- No secrets printed or stored; only hashes and lengths recorded.
