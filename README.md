# YuniTrack OS — Deterministic, Fail-Closed Evidence Harness for Agent Governance
Proof-grade harness for agent governance that emits bounded, reproducible evidence on every run.

## Quick Verify (copy/paste)
```bash
./scripts/prove.sh
./scripts/prove_enterprise.sh
./scripts/prove_lite.sh
```
All commands emit bounded PASS/FAIL lines and generate artifacts under `artifacts/`.

## What you get (artifacts)
- `artifacts/compliance/evidence_report.html` (offline HTML evidence report) and `artifacts/compliance/evidence_report.json`.
- `artifacts/attestations/evidence_pack.dsse.json` + `.sig` + `attestation_index.json`; verify with `scripts/attest/verify_attestation.sh`.
- `artifacts/audit/index_manifest.json`, `artifacts/audit/evidence_pack_index.json`, `artifacts/audit/evidence.zip`; verify with `scripts/audit/verify_evidence_pack.sh`.
- `artifacts/security/gdpr_findings.json` and `artifacts/security/gdpr_compliance_statement.json` (counts-only GDPR scan).
- `artifacts/compliance/ai_act_report.md` and `artifacts/compliance/ai_act_report.json` (evidence mapping, not legal advice).
- `artifacts/trace*/` deterministic trace captures (e.g., `artifacts/trace`, `artifacts/trace_langchain`, `artifacts/trace_otel`) plus run manifests.
- `artifacts/ux/*` offline UX snapshots (text + HTML) when present.
- Proof summaries: `artifacts/proof_report.json`, `artifacts/proof_report_enterprise.json`, and `artifacts/proof_report_lite.json`.

## Security model (short)
- Fail-closed gates: missing hashes or mismatched signatures default to FAIL.
- Deterministic ordering: identical vector inputs yield identical record frames and hashes.
- Bounded output discipline: proofs emit bounded PASS/FAIL lines and capped artifacts.
- Bucket discipline: audit / metrics / security artifacts are separated and hashed independently.
- No-feedback constraints (Lite): actor path receives only tick + tick_hash, no validator hints.
- Domain-separated approvals (DOMAIN_PREFIX `YUNITRACK_APPROVAL_V1\0`) for signature binding.
- Offline verification: manifests and attestations allow replay without network access.

## Non-goals / no claims
- Not legal advice; provides evidence mapping only.
- Does not make LLM outputs "correct."
- No wallclock heartbeat claim.

## Documentation pointers
- `SECURITY_MODEL.md`
- `PROOF.md`
- `CANON.txt`
- `docs/runbooks/operator_one_command.md`
- `docs/handover/ARTIFACT_MAP.md`
- `docs/handover/PROCUREMENT_PACKET.md`
- `docs/handover/RELEASE_CHECKLIST.md`
- `docs/handover/public_git_readiness_report.md`

## License
License: MIT (see LICENSE).

## Minimal contribution note
Issues/PRs welcome.
