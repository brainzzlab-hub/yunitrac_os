#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGED="$ROOT/artifacts/control_plane/hitl_markers_staged.json"
SIGNED="$ROOT/artifacts/control_plane/hitl_markers_signed.json"
KEY="${HITL_SIGNING_KEY_PATH:-}"

if [ -z "$KEY" ]; then
  echo "FAIL: hitl_sign SEC_SIGN_KEY_MISSING"
  exit 1
fi
if [ ! -f "$KEY" ]; then
  echo "FAIL: hitl_sign SEC_SIGN_KEY_MISSING"
  exit 1
fi
if [ ! -f "$STAGED" ]; then
  echo "FAIL: hitl_sign SEC_STAGED_MISSING"
  exit 1
fi

if python3 "$ROOT/tools/hitl_approvals/main.py" sign --key "$KEY" --in "$STAGED" --out "$SIGNED" >/tmp/hitl_sign.log 2>&1; then
  echo "PASS: hitl_sign"
  exit 0
else
  echo "FAIL: hitl_sign SEC_HITL_SIGN_FAIL"
  exit 1
fi
