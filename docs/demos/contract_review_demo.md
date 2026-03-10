# Contract Review Demo (Deterministic, Offline by Default)

## Goal
Show an end-to-end flow: task hash → LLM bridge (dry run) → runbook proofs → evidence verification → dashboard preview. No task text or model output is stored; only hashes/lengths.

## Command (example, dry run)
```bash
./scripts/demo/contract_review_demo.sh \
  --task_file /tmp/demo_task.txt \
  --canon_hash_hex 0000000000000000000000000000000000000000000000000000000000000000 \
  --tick_hash_hex  1111111111111111111111111111111111111111111111111111111111111111 \
  --tick 0 \
  --sliders 80,60,60,60 \
  --provider none \
  --forward 0
```

## What it does (fixed order)
1) Hashes the task file (no content stored).
2) Runs LLM bridge (dry-run by default; payload empty; deterministic proposal.bin + manifests).
3) Runs runbook_operator (proofs + evidence exports).
4) Verifies evidence pack.
5) Runs dashboard_operator to refresh UX outputs.
6) Stores deterministic artifacts under `artifacts/demo/contract_review/<run_id>/`.

## Outputs (hash-only)
- `demo_manifest.json` (run_id, task_sha256/len, mode/sliders, provider/forward)
- `llm_bridge/` proposal artifacts
- `runbook/` (runbook_report.json, evidence_pack_index.json if present)
- `ux/` (dashboard preview/text)

## Safety & determinism
- Offline by default (provider=none, forward=0).
- No task text or model output is persisted; only SHA256 and lengths.
- run_id = sha256(canon_hash_hex:tick_hash_hex:tick:sliders:task_sha256)[0:16].
- All JSON uses sorted keys; no timestamps; stable ordering.
