#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IN_PATH=""
OUT_DIR="$ROOT/artifacts/trace/run"
RULES="$ROOT/docs/specs/gdpr_default_scrub_rules.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --in)
      IN_PATH="$2"; shift 2;;
    --out_dir)
      OUT_DIR="$2"; shift 2;;
    --rules)
      RULES="$2"; shift 2;;
    *)
      shift;;
  esac
done

if [[ -z "$IN_PATH" ]]; then
  echo "FAIL: trace_ingest TRACE_BAD_ARGS"
  exit 1
fi

mkdir -p "$OUT_DIR"

python3 "$ROOT/tools/trace_ingest/main.py" \
  --in "$IN_PATH" \
  --out_dir "$OUT_DIR" \
  --rules "$RULES"
