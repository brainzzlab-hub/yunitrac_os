#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART="$ROOT/artifacts"
VEC="$ROOT/tests/vectors/vector1.json"
AUDIT_KEY="$ROOT/secrets/audit_key.bin"

mkdir -p "$ART/runA" "$ART/runB" "$ROOT/secrets"

# Canon code bytes = raw contents of CANON.txt, base64-encoded for the vector.
CANON_CODE_B64=$(base64 < "$ROOT/CANON.txt" | tr -d '\n')

# Inject canon_code_bytes into vector (temporary files for runA/runB).
TMP_VEC_A="$ART/vector_a.json"
TMP_VEC_B="$ART/vector_b.json"
python3 - "$VEC" "$CANON_CODE_B64" "$TMP_VEC_A" <<'PY'
import json, sys
src, code_b64, out = sys.argv[1:4]
with open(src, 'r', encoding='utf-8') as f:
    data = json.load(f)
data['canon_code_bytes'] = code_b64
with open(out, 'w', encoding='utf-8') as f:
    json.dump(data, f, separators=(',', ':'))
PY
cp "$TMP_VEC_A" "$TMP_VEC_B"

# Audit key (HMAC) generated deterministically for proof (not committed).
if [ ! -f "$AUDIT_KEY" ]; then
  dd if=/dev/zero bs=32 count=1 of="$AUDIT_KEY" 2>/dev/null
fi

cargo build --release

BIN_BOUNDARY="$ROOT/target/release/yuni_boundary"
BIN_VERIFY="$ROOT/target/release/yuni_verify"

"$BIN_BOUNDARY" --vector "$TMP_VEC_A" --audit-key "$AUDIT_KEY" --out "$ART/runA"
"$BIN_BOUNDARY" --vector "$TMP_VEC_B" --audit-key "$AUDIT_KEY" --out "$ART/runB"

"$BIN_VERIFY" --a "$ART/runA" --b "$ART/runB" --audit-key "$AUDIT_KEY" --report "$ART/proof_report.json"

cat "$ART/proof_report.json"
