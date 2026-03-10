#!/usr/bin/env bash
set -euo pipefail

# Fail-closed audit-chain presence/validity check.
# Success: silent exit 0.
# Failure: bounded SECURITY line only.

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

CHAIN_FILES=()
while IFS= read -r line; do
  CHAIN_FILES+=("$line")
done < <(find "$ROOT/artifacts" -type f -name "chain_verification.json" 2>/dev/null | sort)

if [ "${#CHAIN_FILES[@]}" -eq 0 ]; then
  echo "SECURITY: AUDIT_CHAIN_MISSING"
  exit 1
fi

for f in "${CHAIN_FILES[@]}"; do
  python3 - "$f" <<'PY' || { echo "SECURITY: AUDIT_CHAIN_INVALID"; exit 1; }
import json, sys, pathlib
path = pathlib.Path(sys.argv[1])
if path.stat().st_size == 0:
    sys.exit(1)
data = json.loads(path.read_text())
# Minimal structural checks:
# - Must be dict
# - Either has top-level "pass" bool, or per-run entries each with pass bool.
if not isinstance(data, dict):
    sys.exit(1)
if "pass" in data:
    if not isinstance(data["pass"], bool):
        sys.exit(1)
    sys.exit(0)
# per-run structure
passes = []
for v in data.values():
    if isinstance(v, dict) and "pass" in v and isinstance(v["pass"], bool):
        passes.append(v["pass"])
if not passes:
    sys.exit(1)
if not all(passes):
    sys.exit(1)
sys.exit(0)
PY
done

exit 0
