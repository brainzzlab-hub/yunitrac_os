#!/usr/bin/env bash
set -euo pipefail

# Fail-closed metrics covert-channel guard.
# Success: silent exit 0.
# Failure: prints bounded SECURITY line and exits non-zero.

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Collect candidate metric artifacts (portable to older bash on macOS).
METRIC_FILES=()
while IFS= read -r line; do
  METRIC_FILES+=("$line")
done < <(find "$ROOT/artifacts" -type f \( -iname "*metrics*" -o -path "*/METRICS/*" \) 2>/dev/null | sort)

# No metric artifacts → nothing to scan; success.
if [ "${#METRIC_FILES[@]}" -eq 0 ]; then
  exit 0
fi

for f in "${METRIC_FILES[@]}"; do
  # Skip binary files to avoid false positives; focus on text metrics.
  if ! grep -Iq . "$f"; then
    continue
  fi

  # Forbidden keywords that would leak payload/reasons/keys.
  if rg -q -i "payload|reason|schema|validator|signature|pubkey|public key|hint|debug|near-pass" "$f"; then
    echo "SECURITY: METRICS_COVERT_CHANNEL_FAIL"
    exit 1
  fi

  # Reject label-style patterns (e.g., prometheus name{label="..."}).
  if rg -q '^[A-Za-z_:][A-Za-z0-9_:]*\{' "$f"; then
    echo "SECURITY: METRICS_COVERT_CHANNEL_FAIL"
    exit 1
  fi

  # Reject non-numeric values in simple key=value lines.
  if rg -q '=[^0-9\-\n]' "$f"; then
    echo "SECURITY: METRICS_COVERT_CHANNEL_FAIL"
    exit 1
  fi
done

exit 0
