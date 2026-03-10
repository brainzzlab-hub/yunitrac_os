#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE="$ROOT/artifacts/control_plane/ledger_state.json"
python3 "$ROOT/tools/control_plane_ledger/main.py" init --state "$STATE" >/tmp/cp_ledger.log 2>&1 && { echo "PASS: ledger_init"; exit 0; }
echo "FAIL: ledger_init CP_LEDGER_BAD"
exit 1
