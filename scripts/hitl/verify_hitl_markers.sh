#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SIGNED="$ROOT/artifacts/control_plane/hitl_markers_signed.json"
PUBKEY="${HITL_APPROVALS_PUBKEY_PATH:-$ROOT/docs/keys/hitl_approvals_pubkey.pem}"

if [ ! -f "$SIGNED" ]; then
  echo "FAIL: hitl_verify SEC_SIGNED_MISSING"
  exit 1
fi
if [ ! -f "$PUBKEY" ]; then
  echo "FAIL: hitl_verify SEC_PUBKEY_MISSING"
  exit 1
fi

if python3 "$ROOT/tools/hitl_approvals/main.py" verify --pubkey "$PUBKEY" --in "$SIGNED" >/tmp/hitl_verify.log 2>&1; then
  echo "PASS: hitl_verify"
  exit 0
else
  echo "FAIL: hitl_verify SEC_HITL_VERIFY_FAIL"
  exit 1
fi
