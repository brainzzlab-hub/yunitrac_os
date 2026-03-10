# AI Act Evidence Report (Deterministic, No PII)

Purpose: map existing Yunitrack artifacts to EU AI Act evidence pointers (Articles 13, 17, Annex IV). Produces deterministic markdown + JSON summaries. No task text or model output is included.

Usage (after proofs/runbook already generated):
```bash
python3 tools/ai_act_report/main.py \
  --evidence_index artifacts/audit/evidence_pack_index.json \
  --out_md artifacts/compliance/ai_act_report.md \
  --out_json artifacts/compliance/ai_act_report.json
```

Requirements:
- Stdlib only; offline.
- Required artifacts must exist: evidence_pack_index.json, runbook_report.json, license_policy_report.json.
- Fails closed with bounded SecCode via wrapper script.

Outputs:
- Markdown report (deterministic; no timestamps).
- JSON summary: version, required_present flag, counts per section, total referenced artifacts.
