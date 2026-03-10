#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PUBKEY=""
REGISTRY="$ROOT/docs/keys/hitl_key_registry.json"
DSSE="$ROOT/artifacts/attestations/evidence_pack.dsse.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pubkey)
      PUBKEY="$2"; shift 2;;
    --registry)
      REGISTRY="$2"; shift 2;;
    --dsse)
      DSSE="$2"; shift 2;;
    *)
      shift;;
  esac
done

python3 "$ROOT/tools/attestation_dsse/main.py" \
  --mode verify \
  --dsse "$DSSE" \
  ${PUBKEY:+--pubkey "$PUBKEY"} \
  --registry "$REGISTRY"
