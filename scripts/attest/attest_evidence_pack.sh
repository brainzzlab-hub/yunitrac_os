#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KEY=""
REGISTRY="$ROOT/docs/keys/hitl_key_registry.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)
      KEY="$2"; shift 2;;
    --registry)
      REGISTRY="$2"; shift 2;;
    *)
      shift;;
  esac
done

if [[ -z "$KEY" ]]; then
  echo "FAIL: attest_dsse ATTEST_KEY_MISSING"
  exit 1
fi

python3 "$ROOT/tools/attestation_dsse/main.py" \
  --mode attest \
  --key "$KEY" \
  --registry "$REGISTRY"
