#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LEDGER="$ROOT/artifacts/control_plane/action_ledger.jsonl"
SIGNED="$ROOT/artifacts/control_plane/action_ledger_signed.json"
KEY="${CONTROL_PLANE_SIGNING_KEY_PATH:-}"
INCIDENT="$ROOT/artifacts/incident/control_plane_ledger_failure.json"
if [ -z "$KEY" ] || [ ! -f "$KEY" ]; then
  echo "FAIL: ledger_verify CP_LEDGER_MISSING"
  exit 60
fi
if python3 "$ROOT/tools/control_plane_ledger/main.py" verify --key "$KEY" --infile "$SIGNED" --ledger "$LEDGER" >/tmp/cp_ledger.log 2>&1; then
  echo "PASS: ledger_verify"
  exit 0
else
  mkdir -p "$ROOT/artifacts/incident"
  echo '{"version":"1.0","generated_utc":"1970-01-01T00:00:00Z","seccode":"CP_LEDGER_SIG_BAD"}' > "$INCIDENT"
  echo "FAIL: ledger_verify CP_LEDGER_SIG_BAD"
  exit 63
fi
