#!/usr/bin/env bash
# Deterministic operator runbook wrapper: runs proofs + gates + exports with bounded output.
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$WORKDIR"

REPORT_DIR="$WORKDIR/artifacts/control_plane"
REPORT_PATH="$REPORT_DIR/runbook_report.json"
LOG_DIR="$REPORT_DIR/runbook_logs"
mkdir -p "$REPORT_DIR" "$LOG_DIR"

overall="PASS"
steps_json=()
now_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

record_step() {
  local name="$1" result="$2" seccode="$3"
  steps_json+=("{\"name\":\"${name}\",\"result\":\"${result}\",\"seccode\":\"${seccode}\"}")
  if [ "$result" != "PASS" ]; then
    overall="FAIL"
  fi
}

run_step() {
  local name="$1" seccode_fail="$2" cmd="$3"
  local log="$LOG_DIR/${name}.log"
  if eval "$cmd" >"$log" 2>&1; then
    record_step "$name" "PASS" ""
    ledger_record "$name" "PASS" ""
  else
    record_step "$name" "FAIL" "$seccode_fail"
    ledger_record "$name" "FAIL" "$seccode_fail"
  fi
}

# Optional control-plane ledger integration
ledger_init=0
if [ -x "$WORKDIR/scripts/control_plane/ledger_init.sh" ] && \
   [ -x "$WORKDIR/scripts/control_plane/ledger_record.sh" ]; then
  ledger_init=1
  mkdir -p "$WORKDIR/artifacts/control_plane"
  if [ ! -f "$WORKDIR/artifacts/control_plane/ledger_state.json" ]; then
    WORKDIR="$WORKDIR" "$WORKDIR/scripts/control_plane/ledger_init.sh" >/dev/null 2>&1 || true
  fi
fi

ledger_record() {
  local action="$1" result="$2" seccode="$3"
  [ "$ledger_init" -eq 1 ] || return 0
  WORKDIR="$WORKDIR" "$WORKDIR/scripts/control_plane/ledger_record.sh" "$action" "$result" "$seccode" >/dev/null 2>&1 || true
}

sign_and_verify_ledger() {
  [ "$ledger_init" -eq 1 ] || return 0
  if [ -n "${CONTROL_PLANE_SIGNING_KEY_PATH:-}" ] && [ -x "$WORKDIR/scripts/control_plane/ledger_sign.sh" ]; then
    WORKDIR="$WORKDIR" CONTROL_PLANE_SIGNING_KEY_PATH="$CONTROL_PLANE_SIGNING_KEY_PATH" \
      "$WORKDIR/scripts/control_plane/ledger_sign.sh" >/dev/null 2>&1 || return 1
    if [ -x "$WORKDIR/scripts/control_plane/ledger_verify.sh" ]; then
      WORKDIR="$WORKDIR" CONTROL_PLANE_SIGNING_KEY_PATH="$CONTROL_PLANE_SIGNING_KEY_PATH" \
        "$WORKDIR/scripts/control_plane/ledger_verify.sh" >/dev/null 2>&1 || return 1
    fi
  fi
  return 0
}

# Sequenced steps
run_step "prove_enterprise" "SEC_RUNBOOK_PROVE_ENT" "$WORKDIR/scripts/prove_enterprise.sh"
run_step "prove_lite" "SEC_RUNBOOK_PROVE_LITE" "$WORKDIR/scripts/prove_lite.sh"
run_step "generate_sbom" "SEC_RUNBOOK_SBOM" "$WORKDIR/scripts/sbom/generate_sbom.sh"
run_step "license_policy_gate" "SEC_RUNBOOK_LICENSE" "$WORKDIR/scripts/sbom/license_policy_gate.sh"
run_step "export_audit_packet" "SEC_RUNBOOK_AUDIT_EXPORT" "$WORKDIR/scripts/audit/export_audit_packet.sh"
run_step "export_incident_bundle" "SEC_RUNBOOK_INCIDENT_EXPORT" "$WORKDIR/scripts/incident/export_incident_bundle.sh"
ledger_ok="PASS"
if ! sign_and_verify_ledger; then
  ledger_ok="FAIL"
  overall="FAIL"
fi

# Emit runbook report (deterministic ordering)
json_payload="$(
  printf '{'
  printf '"version":"1.0",'
  printf '"generated_utc":"%s",' "$(now_utc)"
  printf '"steps":['
  printf '%s' "$(IFS=,; echo "${steps_json[*]}")"
  printf '],'
  printf '"ledger":"%s",' "$ledger_ok"
printf '"overall":"%s"' "$overall"
printf '}\n'
)"
printf '%s\n' "$json_payload" >"$REPORT_PATH"

# Evidence index + verifier (not included in report to avoid circular hash)
if "$WORKDIR/scripts/audit/generate_evidence_index.sh" >/dev/null 2>&1; then
  ledger_record "generate_evidence_index" "PASS" ""
else
  ledger_record "generate_evidence_index" "FAIL" "SEC_RUNBOOK_EVIDENCE_INDEX"
  overall="FAIL"
fi
if "$WORKDIR/scripts/audit/verify_evidence_pack.sh" >/dev/null 2>&1; then
  ledger_record "verify_evidence_pack" "PASS" ""
else
  ledger_record "verify_evidence_pack" "FAIL" "SEC_RUNBOOK_EVIDENCE_VERIFY"
  overall="FAIL"
fi

# Final bounded output
if [ "$overall" = "PASS" ]; then
  echo "PASS: runbook_operator"
  exit 0
else
  echo "FAIL: runbook_operator SEC_RUNBOOK_FAIL"
  exit 1
fi
