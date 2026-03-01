# PROOF

`./scripts/prove.sh` executes:
1) Builds release binaries.
2) Runs `yuni_boundary` twice (runA/runB) on the same vector.
3) Runs `yuni_verify` to check byte equality, audit HMAC chain, and GDPR numeric-only metrics.
4) Emits `artifacts/proof_report.json` with PASS/FAIL.

Artifacts per run:
- outputs.bin
- audit_records.bin
- metrics_records.bin
- security_records.bin
- hashes.json (canon_hash, tick_hash_head, audit_chain_head, outputs_hash, metrics_hash)

Evidence of determinism: runA vs runB byte equality and matching hashes.
Audit integrity: HMAC chain head recomputed in verifier.
GDPR: metrics stream validated numeric-only; audit/security content-free (IDs/hashes/codes).
