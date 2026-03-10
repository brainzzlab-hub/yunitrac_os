# Operator Dashboard (read-only, offline)

## Purpose
- Render the current proof/evidence state for enterprise and lite profiles.
- Offline, deterministic, no runtime changes, no network, no telemetry.
- Reads from `artifacts/`; falls back to redacted fixtures when artifacts are absent (clearly indicated as FIXTURE MODE).
- Controlled actions (prove runs, audit/incident exports, HITL marker staging) are **disabled by default**; set `YUNITRACK_DASH_ENABLE_ACTIONS=1` to execute them during generation. When disabled, the dashboard renders the actions section as DISABLED.

## Run (one line)
```
./tools/operator_dashboard/run.sh
```
Output: `tools/operator_dashboard/dist/index.html` (deterministic; no timestamps).

## Data sources (read-only)
- Enterprise: `artifacts/proof_report_enterprise.json`, `artifacts/enterprise/evidence_bundle/chain_verification.json` (if present).
- Lite: `artifacts/proof_report_lite.json`, `artifacts/lite/evidence_bundle/{commands.txt,required_hashes.json,policy_checks.json,manifest.json}`, `artifacts/lite/scope_manifest.json`.
- Request Ledger v1 (optional): `artifacts/ops/request_ledger.ndjson` (NDJSON, see `docs/specs/request_ledger_v1.md`). If absent, fixture is used and banner shows FIXTURE MODE.
- If missing, fixtures under `tools/operator_dashboard/fixtures/` are used and a banner is shown.

## Security posture
- Read-only; no writes outside `dist/`.
- No network calls; stdlib-only Python.
- No PII expected; displays only PASS/FAIL and bounded sets already present in artifacts.
- Lite no-feedback invariant preserved: dashboard surfaces only bounded statuses (ACCEPTED/REJECTED + SecCode already bounded by upstream proofs).

## Determinism note
- Re-running `run.sh` without changing inputs produces byte-identical `dist/index.html`.

## Troubleshooting
- If `python3` missing: install system Python 3.x.
- If artifacts are outdated: re-run `./scripts/prove_enterprise.sh` and `./scripts/prove_lite.sh`, then rerun `run.sh`.
- If ledger absent: dashboard falls back to fixtures and labels as FIXTURE MODE.
