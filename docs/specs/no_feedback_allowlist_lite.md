# Lite No-Feedback Allowlist

Allowed actor-visible tokens
- decision: `ACCEPTED` | `REJECTED`
- seccode: fixed enum in `docs/specs/seccode_lite.md`

Forbidden (must not appear in actor-facing artifacts)
- reason, because, validator, schema, payload, signature, pubkey, public key, near-pass, hint, debug, stack trace

Enforcement scope
- Scripts-based scan over Lite artifacts: `artifacts/lite/**` (including proof_report_lite.json, scope_manifest.json, evidence_bundle files).
- Implemented in `scripts/prove_lite.sh` as a fail-closed leak scan; on hit emits bounded SECURITY line and fails.
