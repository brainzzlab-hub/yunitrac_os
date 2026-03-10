YuniTrack Full Option Handover
==============================

Purpose
- One-stop offline bundle for buyers/jurists: proofs, compliance, attestations, evidence indexes, UX previews, and verifier scripts.

Contents (allowlist only)
- docs/: README, PROOF, SECURITY_MODEL, operator runbook, case studies, handover packet.
- artifacts/: compliance (evidence + AI Act), security (GDPR), attestations (DSSE + sig + index), audit indexes (including evidence.zip), UX previews.
- scripts/: verification helpers (evidence pack, attestation, GDPR scrub scan).
- manifests/: FULL_OPTION_MANIFEST.sha256 (deterministic, sorted, sha256).

Verify integrity
- From repo root: ./scripts/handover/verify_full_option.sh
- Expected output: PASS: verify_full_option SEC_OK

Proof commands (should already be green)
- ./scripts/prove.sh
- ./scripts/prove_enterprise.sh
- ./scripts/prove_lite.sh

Security constraints
- No secrets, keys, tmp artifacts, targets, or dev-only materials are included.
- evidence.zip is allowed; no other files >20MB are present.

