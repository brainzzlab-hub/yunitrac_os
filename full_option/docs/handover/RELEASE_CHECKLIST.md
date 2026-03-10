# Release Checklist (Ops/Procurement)

## Preconditions
- Use repo state as provided; no git changes, no installs.
- Tools present: cargo, python3, tar, openssl (for existing flows), cargo-fuzz optional but not auto-installed.
- Env keys (if available): `CONTROL_PLANE_SIGNING_KEY_PATH`, HITL keys, audit key. Never store private keys in repo.

## One-command proof run
```bash
./scripts/runbook_operator.sh
```
- Expected stdout: `PASS: runbook_operator` (single line) or `FAIL: runbook_operator <SecCode>`.
- Logs (bounded) at `artifacts/control_plane/runbook_logs/`.
- Report: `artifacts/control_plane/runbook_report.json`.

## Evidence pack verification
```bash
./scripts/audit/verify_evidence_pack.sh
```
- Expected stdout: `PASS: verify_evidence_pack` or `FAIL: verify_evidence_pack <SecCode>`.
- Index used: `artifacts/audit/evidence_pack_index.json`.

## Key material handling
- Audit key: `secrets/audit_key.bin` (externally provided; not in repo).
- HITL signing: operator provides key via env (HMAC or ed25519 modes depending on configuration).
- Control-plane ledger signing: `CONTROL_PLANE_SIGNING_KEY_PATH` (HMAC). Keep external and rotated per policy.
- Registries: `docs/keys/*.json` (public info only); rotate by updating registry + signing keys externally.

## Rotation/expiry
- Check registry `not_after_utc` fields before runs.
- Replace keys externally, then update registry JSONs (public paths only), re-run runbook.

## If FAIL
- Note SecCode; do not reuse logs beyond SecCode.
- Rerun the specific failing step with same env after fixing inputs.
- If verifier fails (EVIDPACK_* codes), rebuild evidence via runbook, then rerun verifier.
