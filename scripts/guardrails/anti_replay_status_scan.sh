#!/usr/bin/env bash
set -euo pipefail

# Fail-closed guardrail for cross-run anti-replay evidence.
# Success: silent exit 0 (for enterprise requires ledger present; lite allowed to pass without).
# Failure: bounded SECURITY line, no file paths.

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PROFILE="${1:-enterprise}" # expected: enterprise|lite

LEDGER_FILES=()
while IFS= read -r line; do
  LEDGER_FILES+=("$line")
done < <(find "$ROOT/artifacts" -type f \( -iname "replay_ledger*" -o -iname "anti_replay*" -o -iname "ledger.log" -o -iname "replay.json" \) 2>/dev/null | sort)

if [ "$PROFILE" = "enterprise" ]; then
  if [ "${#LEDGER_FILES[@]}" -eq 0 ]; then
    echo "SECURITY: ANTI_REPLAY_CROSS_RUN_MISSING"
    exit 1
  fi
  exit 0
fi

# Lite: pass even if missing (proof will log note in commands.txt)
exit 0
