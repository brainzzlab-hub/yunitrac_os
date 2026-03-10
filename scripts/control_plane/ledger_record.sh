#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE="$ROOT/artifacts/control_plane/ledger_state.json"
LEDGER="$ROOT/artifacts/control_plane/action_ledger.jsonl"
ACTION="${1:-}"; RESULT="${2:-}"; SECCODE="${3:-}";
if [ -z "$ACTION" ] || [ -z "$RESULT" ] || [ -z "$SECCODE" ]; then
  echo "FAIL: ledger_record CP_LEDGER_BAD"
  exit 1
fi
python3 "$ROOT/tools/control_plane_ledger/main.py" record --state "$STATE" --ledger "$LEDGER" --action "$ACTION" --result "$RESULT" --seccode "$SECCODE" >/tmp/cp_ledger.log 2>&1 && { echo "PASS: ledger_record"; exit 0; }
echo "FAIL: ledger_record CP_LEDGER_BAD"
exit 1
