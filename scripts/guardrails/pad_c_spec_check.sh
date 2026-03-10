#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOC="$ROOT/docs/specs/pad_c_entrypoint.md"
TOKENS=(
  "ShotBible"
  "ShotRequest"
  "GenerationPlan"
  "Determinism"
  "GDPR"
  "No-feedback"
  "Anti-replay"
  "Approvals"
)

fail() { echo "SECURITY: PAD_C_SPEC_MISSING_OR_MALFORMED"; exit 1; }

[ -f "$DOC" ] || fail
for t in "${TOKENS[@]}"; do
  if ! grep -Fq "$t" "$DOC"; then
    fail
  fi
done

exit 0
