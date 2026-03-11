# Deployment Matrix — Dual Profile (Enterprise vs Lite)

## Commands
- Profile E (Enterprise): `./scripts/prove_enterprise.sh`
- Profile L (Lite): `./scripts/prove_lite.sh`

## Proof Artifacts
- Enterprise: `artifacts/proof_report_enterprise.json`
- Lite: `artifacts/proof_report_lite.json`
- Shared lite scope: `artifacts/lite/scope_manifest.json`
- Evidence bundles: `artifacts/*/evidence_bundle/*` (enterprise + lite bundles)

## Capability Matrix
| Capability | Profile E (Enterprise) | Profile L (Lite) |
| --- | --- | --- |
| Diode-grade audit chain | Yes | Yes (lite) |
| Deterministic triple-run outputs | Yes (A/B/C) | Yes (B/C) |
| HITL marker verification | Optional (skip if not required) | Optional (skip if not required) |
| SBOM + license gate | Yes | Yes |
| GDPR scrub scan | Yes | Yes |
| Fuzz build check | Yes | Yes |
| Anti-replay guard | Yes (enterprise profile) | Yes (lite profile) |
| Metrics numeric-only guard | Yes | Yes |
| Scope manifest verification | Not applicable | Yes (scope_manifest_verify) |

## Claims
- Enterprise: deterministic A/B/C runs with audit hash chain, HITL optional, full SBOM/license gate, GDPR scrub, anti-replay, fuzz build required, produces `artifacts/proof_report_enterprise.json` and `artifacts/enterprise/evidence_bundle/*`.
- Lite: deterministic B/C equality over scope/evidence bundle, scope manifest enforced, SBOM/license gate, GDPR scrub, anti-replay (lite), produces `artifacts/proof_report_lite.json`, `artifacts/lite/scope_manifest.json`, and `artifacts/lite/evidence_bundle/*`.

## Non-claims
- Neither profile provides production deployment scripts or networking; both are proof-mode only.
- HITL signatures are optional unless explicitly enabled via environment.
- No runtime access to secrets or external key material is included in these proofs.
