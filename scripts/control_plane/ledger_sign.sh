#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LEDGER="$ROOT/artifacts/control_plane/action_ledger.jsonl"
SIGNED="$ROOT/artifacts/control_plane/action_ledger_signed.json"
KEY="${CONTROL_PLANE_SIGNING_KEY_PATH:-}"
if [ -z "$KEY" ] || [ ! -f "$KEY" ]; then
  echo "FAIL: ledger_sign CP_LEDGER_MISSING"
  exit 60
fi
python3 "$ROOT/tools/control_plane_ledger/main.py" sign --key "$KEY" --infile "$LEDGER" --out "$SIGNED" >/tmp/cp_ledger.log 2>&1 && { echo "PASS: ledger_sign"; exit 0; }
echo "FAIL: ledger_sign CP_LEDGER_BAD"
exit 1
