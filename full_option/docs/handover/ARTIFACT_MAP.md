# Artifact Map (Deterministic)

| Producer | Artifact | Path | Purpose | Verifier |
| --- | --- | --- | --- | --- |
| prove.sh | proof reports A/B/C | artifacts/proof_report_*.json | Core determinism proof | scripts/prove.sh (built-in) |
| prove_enterprise | evidence bundle | artifacts/evidence_bundle/ | Enterprise proof outputs | scripts/prove_enterprise.sh |
| prove_lite | lite evidence bundle + commands | artifacts/lite/evidence_bundle/ | Lite proof outputs + commands log | scripts/prove_lite.sh |
| runbook_operator | runbook report | artifacts/control_plane/runbook_report.json | Summarizes run steps (bounded) | scripts/runbook_operator.sh |
| SBOM | cyclonedx | artifacts/sbom/cyclonedx.json | SBOM manifest | scripts/sbom/generate_sbom.sh |
| License gate | license_policy_report | artifacts/sbom/license_policy_report.json | License compliance summary | scripts/sbom/license_policy_gate.sh |
| Audit export | audit packet | artifacts/audit/evidence.zip + index_manifest.json | Audit evidence bundle | scripts/audit/export_audit_packet.sh |
| Incident export | incident bundle (optional) | artifacts/incident/incident_bundle.zip + index_manifest.json | Incident-focused bundle | scripts/incident/export_incident_bundle.sh |
| Evidence index | evidence_pack_index | artifacts/audit/evidence_pack_index.json | Inventory of key artifacts with hashes/sizes | scripts/audit/generate_evidence_index.sh |
| Pack verifier | verification result | stdout: `PASS: verify_evidence_pack` | Offline validation of evidence_pack_index | scripts/audit/verify_evidence_pack.sh |

- Optional artifacts: `artifacts/security/gdpr_findings.json`, `artifacts/control_plane/action_ledger_signed.json`, incident bundle (if present).
- Ledger files: `artifacts/control_plane/ledger_state.json`, `action_ledger.jsonl`, `action_ledger_signed.json` (if signing enabled).
