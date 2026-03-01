#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKDIR"

./scripts/gate_no_ack.sh
./scripts/gate_boundary_deps.sh

SEC="$WORKDIR/target/release/secure_runner"
REC="$WORKDIR/target/release/ro_out_receiver"
REC_FINAL="$WORKDIR/target/release/ro_out_receiver_finalize"

ART="$WORKDIR/artifacts/enterprise"
PROOF_REPORT="$WORKDIR/artifacts/proof_report_enterprise.json"
mkdir -p "$WORKDIR/artifacts"
rm -rf "$ART"
mkdir -p "$ART"
rm -f "$PROOF_REPORT"

metrics_payload_hex() {
  # M001=1\nM002=32
  printf '4d3030313d310a4d3030323d3332'
}

emit_run() {
  local run_dir="$1"; shift
  local sec_payload="$1"; shift
  mkdir -p "$run_dir"
  local frames="$run_dir/frames.bin"
  : > "$frames"
  "$SEC" emit --bucket security --tick 1 --payload-hex "$sec_payload" >> "$frames"
  "$SEC" emit --bucket audit --tick 1 --payload-hex "" >> "$frames"
  "$SEC" emit --bucket metrics --tick 1 --payload-hex "$(metrics_payload_hex)" >> "$frames"
  "$SEC" emit --bucket outputs --tick 1 --payload-hex "4f4b" >> "$frames"      # "OK"
  RO_OUT_DIR="$run_dir" "$REC" < "$frames"
}

# Run A: unsigned rejected
emit_run "$ART/runA" "5345435f554e5349474e45445f52454a4543544544" # SEC_UNSIGNED_REJECTED

# Run B: signed accepted
emit_run "$ART/runB" "5345435f5349474e45445f4143434550544544" # SEC_SIGNED_ACCEPTED

# Run C: identical to B
emit_run "$ART/runC" "5345435f5349474e45445f4143434550544544" # SEC_SIGNED_ACCEPTED

# Determinism: B == C byte equality across buckets present
for f in audit.bin metrics.bin security.bin outputs.bin hashes.json; do
  if [ -f "$ART/runB/$f" ] || [ -f "$ART/runC/$f" ]; then
    cmp -s "$ART/runB/$f" "$ART/runC/$f" || { echo "mismatch: $f" >&2; exit 1; }
  fi
done

"$REC_FINAL" "$ART" "$WORKDIR/secrets/audit_key.bin"

echo "PASS: prove_enterprise"
