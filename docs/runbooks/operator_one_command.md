# Operator One-Command Runbook

## Purpose
A bounded, deterministic wrapper to run both proof profiles, gates, and exports in one step while recording control-plane ledger entries.

## Command
```bash
./scripts/runbook_operator.sh
```

## What it does (fixed order)
1. `./scripts/prove_enterprise.sh`
2. `./scripts/prove_lite.sh`
3. `./scripts/sbom/generate_sbom.sh`
4. `./scripts/sbom/license_policy_gate.sh`
5. `./scripts/audit/export_audit_packet.sh`
6. `./scripts/incident/export_incident_bundle.sh`
7. `./scripts/audit/generate_evidence_index.sh`
8. `./scripts/audit/verify_evidence_pack.sh`

## Outputs
- `artifacts/control_plane/runbook_report.json` (versioned, sorted, PASS/FAIL + SecCode only)
- `artifacts/audit/evidence_pack_index.json` (hash+size index of required artifacts)
- Existing proof artifacts (enterprise + lite)
- SBOM, license policy report, audit packet, incident bundle (if any)
- Control-plane ledger entries (if ledger scripts present)

## Bounded stdout/stderr
- Final line only: `PASS: runbook_operator` or `FAIL: runbook_operator SEC_RUNBOOK_FAIL`
- Intermediate output is suppressed to logs under `artifacts/control_plane/runbook_logs/` (deterministic filenames).

## Ledger integration (optional, fail-closed when enabled)
- If `scripts/control_plane/ledger_*` scripts exist, the runbook will:
  - init ledger if missing
  - record each step result
  - sign and verify if `CONTROL_PLANE_SIGNING_KEY_PATH` is set
- On ledger sign/verify failure, runbook fails with `SEC_RUNBOOK_FAIL`.

## Environment knobs
- `CONTROL_PLANE_SIGNING_KEY_PATH`: enable ledger signing/verification (HMAC key path).

## SecCodes used
- `SEC_RUNBOOK_PROVE_ENT`
- `SEC_RUNBOOK_PROVE_LITE`
- `SEC_RUNBOOK_SBOM`
- `SEC_RUNBOOK_LICENSE`
- `SEC_RUNBOOK_AUDIT_EXPORT`
- `SEC_RUNBOOK_INCIDENT_EXPORT`
- `SEC_RUNBOOK_EVIDENCE_INDEX`
- `SEC_RUNBOOK_EVIDENCE_VERIFY`
- `SEC_RUNBOOK_FAIL`

## Procurement/offline verification
- Run `./scripts/audit/verify_evidence_pack.sh` to validate hashes/sizes of the indexed artifacts offline using `artifacts/audit/evidence_pack_index.json`.
