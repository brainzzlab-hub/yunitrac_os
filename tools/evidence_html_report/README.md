# Evidence HTML Report

Purpose: generate a deterministic, PII-free HTML evidence summary for stakeholders.

Usage:
```bash
python3 tools/evidence_html_report/main.py \
  --evidence_index artifacts/audit/evidence_pack_index.json \
  --out_html artifacts/compliance/evidence_report.html \
  --out_json artifacts/compliance/evidence_report.json
```

Rules:
- Required input: evidence_pack_index.json
- Optional inputs auto-included if present: runbook_report.json, gdpr_findings.json, license_policy_report.json, audit/incident manifests.
- No timestamps; stable ordering; hashes/sizes only.
- Stdout: `PASS: evidence_html_report` or bounded FAIL with SecCode.
