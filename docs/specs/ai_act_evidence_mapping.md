# EU AI Act Evidence Mapping (Yunitrack)

Scope: provide deterministic, artifact-backed evidence pointers for Articles 13 & 17 and Annex IV. This is NOT legal advice or compliance attestation.

Principles
- Outside boundary only; no runtime changes.
- Deterministic output: no timestamps, no environment-derived data, stable ordering.
- No PII: report includes only hashes, sizes, labels, SecCodes; never task text or model output.
- Fail-closed if required artifacts are missing or malformed.

Inputs (deterministic, no timestamps)
- Required: `artifacts/audit/evidence_pack_index.json`, `artifacts/compliance/evidence_report.json`, `artifacts/attestations/attestation_index.json` (or `artifacts/attestations/evidence_pack.dsse.json` fallback)
- Optional: `artifacts/security/gdpr_compliance_statement.json`, `artifacts/sbom/license_policy_report.json`, `artifacts/control_plane/runbook_report.json`, `artifacts/audit/index_manifest.json`, `artifacts/incident/index_manifest.json`, `artifacts/trace/run/*/trace_evidence_index.json`, `artifacts/trace_otel/run/*/trace_evidence_index.json`

Outputs
- `artifacts/compliance/ai_act_report.md` (deterministic markdown)
- `artifacts/compliance/ai_act_report.json` (label+count only; sorted keys)

Mapping approach (evidence pointers only)
- Article 13: instructions/output bounding/attestation present indicators.
- Article 17: QMS indicators → runbook, incident workflow, SBOM/license gate, change-control signals.
- Annex IV: technical documentation → CANON.txt, verification procedures, risk controls (GDPR), audit/trace evidence.
- Cryptographic integrity: approvals are domain-separated with DOMAIN_PREFIX YUNITRACK_APPROVAL_V1\0 (protocol-binding).

Gaps (always listed)
- Intended purpose statement, deployment context, human oversight procedures, post-market monitoring plan.
