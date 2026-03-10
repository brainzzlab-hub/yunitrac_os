#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$WORKDIR"

fail() { echo "FAIL: contract_review_demo $1"; exit 1; }

# Defaults
tick=0
sliders="80,60,60,60"
provider="none"
forward=0

while [ $# -gt 0 ]; do
  case "$1" in
    --task_file) task_file="$2"; shift 2 ;;
    --canon_hash_hex) canon_hash_hex="$2"; shift 2 ;;
    --tick_hash_hex) tick_hash_hex="$2"; shift 2 ;;
    --tick) tick="$2"; shift 2 ;;
    --sliders) sliders="$2"; shift 2 ;;
    --provider) provider="$2"; shift 2 ;;
    --forward) forward="$2"; shift 2 ;;
    *) fail "DEMO_BAD_ARGS" ;;
  esac
done

[ -n "${task_file:-}" ] || fail "DEMO_BAD_ARGS"
[ -n "${canon_hash_hex:-}" ] || fail "DEMO_BAD_ARGS"
[ -n "${tick_hash_hex:-}" ] || fail "DEMO_BAD_ARGS"

# Compute task hash
RUN_ROOT="$WORKDIR/artifacts/demo/contract_review"
mkdir -p "$RUN_ROOT"
TASK_HASH_OUT="$RUN_ROOT/task_hash_tmp.json"
python3 tools/demo_task_hash/main.py --task_file "$task_file" --out "$TASK_HASH_OUT" >/dev/null 2>&1 || fail "DEMO_TASK_HASH"
task_sha=$(python3 - <<'PY' "$TASK_HASH_OUT"
import json,sys
data=json.load(open(sys.argv[1]))
print(data["task_sha256"])
PY
)
task_len=$(python3 - <<'PY' "$TASK_HASH_OUT"
import json,sys
data=json.load(open(sys.argv[1]))
print(data["task_len"])
PY
)
rm -f "$TASK_HASH_OUT"

# Determine run_id
run_id=$(python3 - <<'PY' "$canon_hash_hex" "$tick_hash_hex" "$tick" "$sliders" "$task_sha"
import hashlib,sys
s=":".join(sys.argv[1:])
print(hashlib.sha256(s.encode()).hexdigest()[:16])
PY
)
RUN_DIR="$RUN_ROOT/$run_id"
mkdir -p "$RUN_DIR"/{llm_bridge,runbook,ux}

# Step A: LLM bridge (dry run unless provider/forward override)
LLM_OUT="$RUN_DIR/llm_bridge"
mkdir -p "$LLM_OUT"
./scripts/llm_bridge/run_llm_bridge.sh \
  --mode ANALYZE \
  --canon_hash_hex "$canon_hash_hex" \
  --tick_hash_hex "$tick_hash_hex" \
  --tick "$tick" \
  --sliders "$sliders" \
  --out_dir "$LLM_OUT" \
  --provider "$provider" \
  --forward "$forward" \
  --max_bytes 4096 >"$RUN_DIR/log_llm_bridge.txt" 2>&1 || fail "DEMO_LLM_BRIDGE_FAIL"

# Step B: runbook + evidence pack verify + dashboard
./scripts/runbook_operator.sh >"$RUN_DIR/log_runbook.txt" 2>&1 || fail "DEMO_RUNBOOK_FAIL"
./scripts/audit/verify_evidence_pack.sh >"$RUN_DIR/log_evidpack.txt" 2>&1 || fail "DEMO_EVIDPACK_FAIL"
./scripts/dashboard_operator.sh >"$RUN_DIR/log_dashboard.txt" 2>&1 || fail "DEMO_DASHBOARD_FAIL"

# Copy minimal artifacts
cp -f artifacts/control_plane/runbook_report.json "$RUN_DIR/runbook/" 2>/dev/null || true
cp -f artifacts/audit/evidence_pack_index.json "$RUN_DIR/runbook/" 2>/dev/null || true
cp -f artifacts/ux/dashboard_preview.html "$RUN_DIR/ux/" 2>/dev/null || true
cp -f artifacts/ux/dashboard_1.txt "$RUN_DIR/ux/" 2>/dev/null || true
cp -f artifacts/ux/dashboard_2.txt "$RUN_DIR/ux/" 2>/dev/null || true

# Build demo manifest
python3 - <<'PY' "$RUN_DIR" "$run_id" "$task_sha" "$task_len" "$canon_hash_hex" "$tick_hash_hex" "$tick" "$sliders" "$provider" "$forward"
import json,sys
run_dir, run_id, task_sha, task_len, canon_hash, tick_hash, tick, sliders, provider, forward = sys.argv[1:]
manifest = {
    "version":"1.0",
    "run_id": run_id,
    "task_sha256": task_sha,
    "task_len": int(task_len),
    "mode":"ANALYZE",
    "sliders": sliders,
    "canon_hash_hex": canon_hash,
    "tick_hash_hex": tick_hash,
    "tick": int(tick),
    "provider": provider,
    "forward": int(forward),
    "artifacts": {
        "llm_bridge": "llm_bridge/",
        "runbook": "runbook/",
        "ux": "ux/"
    }
}
(Path:=__import__("pathlib").Path)(run_dir, "demo_manifest.json").write_text(
    json.dumps(manifest, sort_keys=True, separators=(",",":")) + "\\n", encoding="utf-8"
)
PY

echo "PASS: contract_review_demo"
