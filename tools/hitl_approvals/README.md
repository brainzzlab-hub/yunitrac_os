# HITL Approvals Toolkit (deterministic, offline)

Purpose: sign and verify HITL marker bundles without introducing new dependencies.

## Artifacts
- Staged (input): `artifacts/control_plane/hitl_markers_staged.json` (sorted, bounded, content-free labels)
- Signed (output): `artifacts/control_plane/hitl_markers_signed.json`
- Public key placeholder: `docs/keys/hitl_approvals_pubkey.pem` (operator-supplied secret key path at runtime)
- Private key: **never stored in repo**; provided via `HITL_SIGNING_KEY_PATH` when signing.

## Commands
- Sign: `python3 tools/hitl_approvals/main.py sign --key <path> --in artifacts/control_plane/hitl_markers_staged.json --out artifacts/control_plane/hitl_markers_signed.json`
- Verify: `python3 tools/hitl_approvals/main.py verify --pubkey <path> --in artifacts/control_plane/hitl_markers_signed.json`

## Determinism & safety
- JSON canonicalization: `sort_keys=True`, `separators=(',', ':')`, items sorted by `id`.
- Signature: HMAC-SHA256 over canonical payload bytes.
- key_id = SHA256(key bytes) hex; included in signature block.
- Bounds: max 100 items; id<=64 chars; label<=128; expires_utc<=64; signature<=256; total payload<=1MB.
- Outputs: single PASS/FAIL line with SecCode; no secrets printed.

## HITL workflow (enterprise)
1. Stage markers (writer-only side).
2. Sign with operator-provided key (`HITL_SIGNING_KEY_PATH`).
3. Verify during proofs using operator-supplied verification key file (`docs/keys/hitl_approvals_pubkey.pem` or override env).

## Lite profile
- Off by default; can opt-in by setting `HITL_LITE_REQUIRED=1` before running `scripts/prove_lite.sh`.

