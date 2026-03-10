#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IN_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --in)
      IN_PATH="$2"; shift 2;;
    *)
      shift;;
  esac
done

if [[ -z "$IN_PATH" ]]; then
  echo "FAIL: langchain_trace_ingest LCH_BAD_ARGS"
  exit 1
fi

python3 "$ROOT/tools/trace_ingest_langchain/main.py" --in "$IN_PATH"
