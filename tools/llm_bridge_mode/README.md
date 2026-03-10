# LLM Bridge Mode (stdlb only)

Purpose: produce deterministic proposal bytes outside the secure boundary. Offline by default; forwarding to an LLM requires explicit `--forward=1` and a supported `--provider`.

Usage (dry run):
```bash
python3 tools/llm_bridge_mode/main.py \
  --mode ANALYZE \
  --canon_hash_hex 000...000 \
  --tick_hash_hex  111...111 \
  --tick 0 \
  --sliders 80,60,60,60 \
  --out_dir artifacts/llm_bridge/demo_run \
  --provider none \
  --forward 0 \
  --max_bytes 4096
```

Outputs (deterministic):
- `proposal.bin`
- `proposal_manifest.json`
- `provider_status.json`
- `audit_stub.json`

Safety:
- No raw task/model text is stored.
- provider calls are disabled unless `--forward=1`.
- Fails closed if provider tooling is missing.
