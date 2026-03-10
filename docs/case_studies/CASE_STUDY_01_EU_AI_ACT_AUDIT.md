# Case Study 01 — EU AI Act Audit (Evidence Mapping, Hash-Only)

Scenario
- Buyer requests offline evidence mapping for AI system governance (Articles 13/17, Annex IV).
- Artifacts already generated; no new runs required.
- Goal: share hashes-only evidence pack + attestation for review.

What the operator runs
- `./scripts/runbook_operator.sh` (produces proofs, evidence pack, reports).
- `./scripts/attest/attest_evidence_pack.sh --key <ed25519_priv.pem>` (offline DSSE attestation).
- Optional ingest demos already produced (LangGraph/OTEL traces via trace_ingest tools).

Artifacts produced (filenames only)
- `artifacts/compliance/evidence_report.html` (hash-only evidence summary)
- `artifacts/compliance/ai_act_report.md` (A13/A17/Annex IV mapping)
- `artifacts/audit/evidence_pack_index.json`
- `artifacts/attestations/evidence_pack.dsse.json` (+ `.sig`, `attestation_index.json`)
- `artifacts/trace/run/.../trace_evidence_index.json` (LangGraph) and `artifacts/trace_otel/run/.../trace_evidence_index.json` (OTEL) — counts only

Offline verifiable
- `scripts/audit/verify_evidence_pack.sh` (hash/size check, bounded)
- `scripts/attest/verify_attestation.sh --pubkey <ed25519_pub.pem>` (DSSE signature + subject hashes)
- Proof scripts: `prove.sh`, `prove_enterprise.sh`, `prove_lite.sh` (bounded, deterministic)
- Approval signatures are protocol-bound via domain-separated canonical bytes (DOMAIN_PREFIX YUNITRACK_APPROVAL_V1\0).

What is NOT claimed
- Not legal advice. Evidence mapping only.
- No claim of GDPR/AI Act compliance.
- No content retained; reports carry hashes/counts/SecCodes only.

Mapping pointers (hash-only)
- Transparency/Instructions: `artifacts/compliance/evidence_report.html`
- AI Act checklist: `artifacts/compliance/ai_act_report.md`
- Attestation: `artifacts/attestations/evidence_pack.dsse.json`
- Trace transparency (counts only): `artifacts/trace*/run/*/trace_evidence_index.json`
