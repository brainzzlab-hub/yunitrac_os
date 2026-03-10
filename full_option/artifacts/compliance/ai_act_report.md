# EU AI Act Evidence Mapping (Deterministic, No PII)
_This is an evidence mapping, not a legal opinion or compliance attestation._

## Evidence inventory
- action_ledger_signed: artifacts/control_plane/action_ledger_signed.json (sha256=8a957fde681e043a61949f5f73167b07729ba9f65c9818b103edc3a913571d38, size=311)
- audit_packet_manifest: artifacts/audit/index_manifest.json (sha256=fc50ba6c7c79859ad6335a3a9f0a2f646026d083f43ea020e56da28d4e33bdcc, size=861)
- evidence_pack.dsse.json: artifacts/attestations/attestation_index.json (sha256=c7f5ff485d293be6f07c1b43feb089422a47b2f915d56441d1bc2c84b40767c6, size=1753)
- evidence_pack.dsse.sig: artifacts/attestations/attestation_index.json (sha256=257c75a98a03dd8ec8ce36a41b17cd5905e1c7ad596ded4562261295ab7e5a89, size=87)
- gdpr_findings: artifacts/security/gdpr_findings.json (sha256=fd470ce3ee8c3a91f058c2e7954f768e881cf8fe27e99e2ed03065f72051e862, size=96)
- incident_bundle_manifest: artifacts/incident/index_manifest.json (sha256=8f300886c3040e9a6310710625b595693dcb54f4489d379e372f77fd0c20892a, size=1122)
- license_policy_report: artifacts/sbom/license_policy_report.json (sha256=c4f7ea9c73ba3478f984fa22b23e4b70ff2ed28f02b6ca77ce77c95cda3438ba, size=111)
- runbook_report: artifacts/control_plane/runbook_report.json (sha256=f7c17571249229db990ffbb50bb7c4a0b3e994505e42ae175a460030b863fbb3, size=445)
- sbom_cyclonedx: artifacts/sbom/cyclonedx.json (sha256=3d2620ca89dded596be9d574aef82ef5baacb2cd617ff182c797dd4a872a5eab, size=63)

### Article 13 (Transparency / Instructions for use)
- [PRESENT] Instructions present (refs: evidence_report.json)
- [PRESENT] Auditability evidence (refs: evidence_pack_index.json)
- [PRESENT] Output bounding evidence (refs: gdpr_compliance_statement.json)
- [PRESENT] Attestation present (refs: attestation_index.json)

### Article 17 (Quality management system)
- [PRESENT] Runbook procedure (refs: runbook_report.json)
- [PRESENT] Incident workflow evidence (refs: incident/index_manifest.json)
- [PRESENT] SBOM & license policy gate (refs: license_policy_report.json)
- [PRESENT] Change control signals (proof scripts/verifiers) (refs: prove.sh, prove_enterprise.sh, prove_lite.sh, verify_evidence_pack.sh)

### Annex IV (Technical documentation)
- [PRESENT] System description docs (refs: CANON.txt)
- [PRESENT] Verification procedure (refs: scripts/prove.sh)
- [PRESENT] Risk controls evidence (GDPR) (refs: gdpr_compliance_statement.json)
- [PRESENT] Logs/audit structure (refs: evidence_pack_index.json)
- [PRESENT] Trace ingestion evidence (refs: trace/run/.../trace_evidence_index.json)

## Gaps / operator inputs needed
- Intended purpose and deployment context
- Human oversight and intervention procedures
- Post-market monitoring plan
