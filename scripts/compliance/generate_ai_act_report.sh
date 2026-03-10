#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$WORKDIR"

OUT_DIR="$WORKDIR/artifacts/compliance"
mkdir -p "$OUT_DIR"

if python3 tools/ai_act_report/main.py \
  --out_md artifacts/compliance/ai_act_report.md \
  --out_json artifacts/compliance/ai_act_report.json; then
  echo "PASS: ai_act_report"
else
  # main.py already prints bounded FAIL line
  exit 1
fi
