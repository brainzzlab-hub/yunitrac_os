#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$WORKDIR"

mkdir -p artifacts/compliance

python3 tools/evidence_html_report/main.py \
  --evidence_index artifacts/audit/evidence_pack_index.json \
  --out_html artifacts/compliance/evidence_report.html \
  --out_json artifacts/compliance/evidence_report.json
