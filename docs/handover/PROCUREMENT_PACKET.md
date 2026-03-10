# Procurement Packet (5-minute Verification)

## What to request
- Current repo state (this workspace).
- Generated artifacts directory (artifacts/*) including SBOM, license report, audit/incident bundles, evidence_pack_index.json.
- Any required public registries (`docs/keys/*.json`); no private keys.

## Steps (offline friendly)
1. Run one-command proof:
   ```bash
   ./scripts/runbook_operator.sh
   ```
   - Expect `PASS: runbook_operator` (single line). If FAIL, note SecCode.
2. Verify evidence pack:
   ```bash
   ./scripts/audit/verify_evidence_pack.sh
   ```
   - Expect `PASS: verify_evidence_pack` or bounded FAIL with SecCode.
3. (Optional) Re-run standalone proofs if desired:
   - `./scripts/prove_enterprise.sh`
   - `./scripts/prove_lite.sh`

## How to interpret results
- PASS lines only; any FAIL includes SecCode for triage.
- Evidence index: `artifacts/audit/evidence_pack_index.json` lists hashed files; verifier checks size/hash and inspects zips for forbidden file types.

## If FAIL
- Do not inspect contents; capture SecCode.
- Re-run runbook after ensuring required files/keys are present.
- For EVIDPACK_ZIP_* codes: regenerate audit/incident bundles via runbook, then rerun verifier.
