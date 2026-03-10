# Case Study 02 — Multi-Agent Incident / SOC (Hash-Only, Offline)

Scenario
- SOC receives multi-agent incident signals; needs bounded, hash-only evidence for triage.
- Trace ledgers (LangChain/OTEL) already ingested; incident bundle available.
- CISO wants verifiable artifacts without exposing content/PII.

What the operator runs
- `./scripts/runbook_operator.sh` (proofs, evidence pack, incident bundle export if present).
- `./scripts/trace_ingest/run_langchain_ledger_ingest.sh --in artifacts/control_plane/action_ledger.jsonl` (hash-only agent ledger → Trace Contract v1).
- `./scripts/attest/verify_attestation.sh --pubkey <ed25519_pub.pem>` (verify DSSE attestation).

Artifacts produced (filenames only)
- `artifacts/incident/index_manifest.json` (if incidents bundled)
- `artifacts/trace_langchain/run/.../trace_evidence_index.json` (LangChain hash-only ledger)
- `artifacts/trace_otel/run/.../trace_evidence_index.json` (OTEL spans, counts only)
- `artifacts/compliance/evidence_report.html` (summary)
- `artifacts/attestations/evidence_pack.dsse.json` (+ `.sig`, `attestation_index.json`)

Offline verifiable
- `scripts/audit/verify_evidence_pack.sh` (hash/size check)
- `scripts/attest/verify_attestation.sh` (signature + subject hashes)
- Proof scripts (`prove.sh`, `prove_enterprise.sh`, `prove_lite.sh`) for deterministic builds

Integrity guarantees
- Approval signatures are protocol-bound via domain-separated canonical bytes (DOMAIN_PREFIX YUNITRACK_APPROVAL_V1\0).

What is NOT claimed
- Not legal advice or compliance guarantee.
- No task text, prompts, or outputs stored; hash+len only, SecCodes bounded.

Mapping pointers (hash-only)
- Incident evidence: `artifacts/incident/index_manifest.json` (if present)
- Trace transparency: `artifacts/trace_langchain/run/*/trace_evidence_index.json`, `artifacts/trace_otel/run/*/trace_evidence_index.json`
- Evidence summary: `artifacts/compliance/evidence_report.html`
- Attestation: `artifacts/attestations/evidence_pack.dsse.json`
