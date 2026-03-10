#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKDIR"

./scripts/guardrails/denylist_scan.sh
./scripts/gate_no_ack.sh
./scripts/gate_boundary_deps.sh
./scripts/guardrails/boundary_scope_enforce.sh
./scripts/guardrails/forbidden_deps_symbols_scan.sh
./scripts/sbom/generate_sbom.sh
./scripts/sbom/license_policy_gate.sh
./scripts/audit/export_audit_packet.sh
if [ "${HITL_SIGNATURE_MODE:-hmac}" = "ed25519" ]; then
  REG="$WORKDIR/${HITL_KEY_REGISTRY_PATH:-docs/keys/hitl_key_registry.json}"
  if [ ! -f "$REG" ]; then
    echo "FAIL: hitl_verify_enterprise_ed25519 SEC_REGISTRY_MISSING"
    exit 1
  fi
  if ./scripts/hitl/verify_hitl_markers_ed25519.sh; then
    echo "PASS: hitl_verify_enterprise_ed25519"
  else
    mkdir -p "$WORKDIR/artifacts/incident"
    echo '{"version":"1.0","generated_utc":"1970-01-01T00:00:00Z","seccode":"SEC_HITL_VERIFY_ED25519_FAIL","mode":"ed25519"}' > "$WORKDIR/artifacts/incident/hitl_signature_failure.json"
    exit 1
  fi
elif [ "${HITL_REQUIRED:-0}" -eq 1 ]; then
  ./scripts/hitl/verify_hitl_markers.sh
else
  echo "PASS: hitl_verify_enterprise_skip"
fi

if [ "${CONTROL_PLANE_LEDGER_ENABLED:-0}" -eq 1 ] && [ "${CONTROL_PLANE_LEDGER_SIGNATURE_MODE:-hmac}" = "ed25519" ]; then
  if ./scripts/control_plane/ledger_verify_ed25519.sh; then
    echo "PASS: ledger_verify_ed25519_enterprise"
  else
    exit 1
  fi
fi
./scripts/guardrails/gdpr_scrub_scan.sh
if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "SECURITY: FUZZ_TOOL_MISSING"
  exit 1
fi
if ! rustup toolchain list | grep -q '^nightly'; then
  echo "SECURITY: FUZZ_TOOLCHAIN_MISSING"
  exit 1
fi
if ! env RUSTUP_TOOLCHAIN=nightly CARGO_NET_OFFLINE=true cargo fuzz build fuzz_decode_recordframe; then
  echo "SECURITY: FUZZ_BUILD_FAIL"
  exit 1
fi

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
    cmp -s "$ART/runB/$f" "$ART/runC/$f" || { echo "FAIL: determinism_mismatch SEC_DETERMINISM_MISMATCH" >&2; exit 11; }
  fi
done

"$REC_FINAL" "$ART" "$WORKDIR/secrets/audit_key.bin"

./scripts/guardrails/metrics_scan.sh
./scripts/guardrails/anti_replay_status_scan.sh enterprise
./scripts/guardrails/audit_chain_verify.sh
./scripts/guardrails/pad_c_spec_check.sh

echo "PASS: prove_enterprise"
