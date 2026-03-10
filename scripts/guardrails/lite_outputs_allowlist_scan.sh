#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Actor-visible Lite outputs to scan. Keep narrow to avoid unrelated files.
FILES=(
  "$ROOT/artifacts/proof_report_lite.json"
)

for f in "${FILES[@]}"; do
  [ -f "$f" ] || { echo "SECURITY: LITE_OUTPUTS_ALLOWLIST_FAIL"; exit 1; }
done

for f in "${FILES[@]}"; do
  # Fail if any forbidden tokens appear (case-insensitive).
  if rg -q -i --fixed-strings \
    -e "reason" -e "because" -e "validator" -e "schema" -e "payload" \
    -e "signature" -e "pubkey" -e "hint" -e "debug" -e "stack" "$f"; then
    echo "SECURITY: LITE_OUTPUTS_ALLOWLIST_FAIL"
    exit 1
  fi
done

exit 0
